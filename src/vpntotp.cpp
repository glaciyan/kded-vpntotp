// kded module: a NetworkManager secret agent that answers VPN password requests with
// "<stored password><current TOTP code>", both read from KWallet.
//
// KWallet layout (network wallet, folder "VPN TOTP"):
//   "<connection uuid>;password"  -> static password
//   "<connection uuid>;totp"      -> base32 TOTP secret
//
// Connections without both entries, retries after a rejected password (RequestNew) and
// non-VPN requests are declined with NoSecrets, so NetworkManager falls through to the
// next agent (Plasma's own dialog).
//
// NetworkManagerQt's SecretAgent can't be used here: it always exports at the fixed agent
// path on the shared system-bus connection, which plasma-nm's agent already occupies in
// the same kded process. So this agent uses its own private system-bus connection.

#include "totp.h"

#include <KDEDModule>
#include <KPluginFactory>
#include <KWallet>
#include <NetworkManagerQt/GenericTypes>

#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusContext>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusObjectPath>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDBusReply>
#include <QDBusServiceWatcher>
#include <QDateTime>
#include <QLoggingCategory>
#include <QPointer>
#include <QTimer>

#include <utility>

Q_LOGGING_CATEGORY(VPNTOTP, "kded.vpntotp", QtInfoMsg)

namespace
{
const QString WalletFolder = QStringLiteral("VPN TOTP");
const QString BusName = QStringLiteral("kded-vpntotp");
const QString NmService = QStringLiteral("org.freedesktop.NetworkManager");
const QString AgentPath = QStringLiteral("/org/freedesktop/NetworkManager/SecretAgent");
const QString NoSecretsError = QStringLiteral("org.freedesktop.NetworkManager.SecretAgent.NoSecrets");
const QString NotAuthorizedError = QStringLiteral("org.freedesktop.NetworkManager.SecretAgent.NotAuthorized");
constexpr uint RequestNew = 0x2;
constexpr uint CapabilityVpnHints = 0x1;
// If fewer seconds than this remain in the current TOTP window, wait for the next code
// so the server doesn't receive one that expires mid-handshake.
constexpr int MinSecondsLeft = 3;
}

class TotpSecretAgent : public QObject, protected QDBusContext
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.freedesktop.NetworkManager.SecretAgent")
public:
    explicit TotpSecretAgent(QObject *parent)
        : QObject(parent)
        , m_bus(QDBusConnection::connectToBus(QDBusConnection::SystemBus, BusName))
    {
        qDBusRegisterMetaType<NMStringMap>();
        qDBusRegisterMetaType<NMVariantMapMap>();

        if (!m_bus.isConnected()) {
            qCWarning(VPNTOTP) << "Cannot connect to the system bus:" << m_bus.lastError().message();
            return;
        }
        if (!m_bus.registerObject(AgentPath, this, QDBusConnection::ExportAllSlots)) {
            qCWarning(VPNTOTP) << "Cannot export the secret agent object";
            return;
        }

        auto *watcher = new QDBusServiceWatcher(NmService, m_bus, QDBusServiceWatcher::WatchForRegistration, this);
        connect(watcher, &QDBusServiceWatcher::serviceRegistered, this, &TotpSecretAgent::registerAgent);
        registerAgent();
    }

    ~TotpSecretAgent() override
    {
        if (m_bus.isConnected()) {
            m_bus.call(QDBusMessage::createMethodCall(NmService,
                                                      QStringLiteral("/org/freedesktop/NetworkManager/AgentManager"),
                                                      QStringLiteral("org.freedesktop.NetworkManager.AgentManager"),
                                                      QStringLiteral("Unregister")),
                       QDBus::Block,
                       1000);
        }
        QDBusConnection::disconnectFromBus(BusName);
    }

public Q_SLOTS:
    NMVariantMapMap GetSecrets(const NMVariantMapMap &connection,
                               const QDBusObjectPath &connectionPath,
                               const QString &settingName,
                               const QStringList &hints,
                               uint flags)
    {
        Q_UNUSED(hints)
        setDelayedReply(true);
        const QDBusMessage msg = message();

        if (!callerIsNetworkManager(msg)) {
            qCWarning(VPNTOTP) << "Rejected GetSecrets from" << msg.service() << "(not NetworkManager)";
            m_bus.send(msg.createErrorReply(NotAuthorizedError, QStringLiteral("Only NetworkManager may ask")));
            return {};
        }

        const QVariantMap conn = connection.value(QStringLiteral("connection"));
        const QString uuid = conn.value(QStringLiteral("uuid")).toString();
        const QString id = conn.value(QStringLiteral("id")).toString();

        if (settingName != QLatin1String("vpn") || conn.value(QStringLiteral("type")).toString() != QLatin1String("vpn")) {
            decline(msg, QStringLiteral("vpntotp only handles VPN secrets"));
            return {};
        }
        if (flags & RequestNew) {
            qCInfo(VPNTOTP) << "Previous password for" << id << "was rejected; deferring to the interactive agent";
            decline(msg, QStringLiteral("Previous secrets were rejected"));
            return {};
        }

        m_pending.append({msg, connectionPath.path(), settingName, uuid, id});
        ensureWallet();
        return {};
    }

    void CancelGetSecrets(const QDBusObjectPath &connectionPath, const QString &settingName)
    {
        m_pending.removeIf([&](const Request &r) {
            return r.path == connectionPath.path() && r.setting == settingName;
        });
    }

    // Never store or delete anything: secrets live only in our KWallet folder.
    void SaveSecrets(const NMVariantMapMap &, const QDBusObjectPath &)
    {
    }

    void DeleteSecrets(const NMVariantMapMap &, const QDBusObjectPath &)
    {
    }

private:
    struct Request {
        QDBusMessage msg;
        QString path;
        QString setting;
        QString uuid;
        QString id;
    };

    void registerAgent()
    {
        QDBusMessage call = QDBusMessage::createMethodCall(NmService,
                                                           QStringLiteral("/org/freedesktop/NetworkManager/AgentManager"),
                                                           QStringLiteral("org.freedesktop.NetworkManager.AgentManager"),
                                                           QStringLiteral("RegisterWithCapabilities"));
        call << QStringLiteral("org.kde.vpntotp") << CapabilityVpnHints;
        auto *w = new QDBusPendingCallWatcher(m_bus.asyncCall(call), this);
        connect(w, &QDBusPendingCallWatcher::finished, this, [](QDBusPendingCallWatcher *w) {
            QDBusPendingReply<> reply = *w;
            if (reply.isError()) {
                qCWarning(VPNTOTP) << "Agent registration failed:" << reply.error().message();
            } else {
                qCInfo(VPNTOTP) << "Registered with NetworkManager";
            }
            w->deleteLater();
        });
    }

    bool callerIsNetworkManager(const QDBusMessage &msg) const
    {
        const QDBusReply<QString> owner = m_bus.interface()->serviceOwner(NmService);
        return owner.isValid() && owner.value() == msg.service();
    }

    void decline(const QDBusMessage &msg, const QString &why)
    {
        m_bus.send(msg.createErrorReply(NoSecretsError, why));
    }

    void ensureWallet()
    {
        if (m_wallet && m_wallet->isOpen()) {
            processPending();
            return;
        }
        if (m_wallet) {
            return; // still opening
        }
        if (!KWallet::Wallet::isEnabled()) {
            failAll(QStringLiteral("KWallet is disabled"));
            return;
        }

        m_wallet = KWallet::Wallet::openWallet(KWallet::Wallet::NetworkWallet(), 0, KWallet::Wallet::Asynchronous);
        if (!m_wallet) {
            failAll(QStringLiteral("Could not open KWallet"));
            return;
        }
        connect(m_wallet, &KWallet::Wallet::walletOpened, this, [this](bool ok) {
            if (!ok) {
                m_wallet->deleteLater();
                m_wallet.clear();
                failAll(QStringLiteral("KWallet could not be opened"));
                return;
            }
            processPending();
        });
        connect(m_wallet, &KWallet::Wallet::walletClosed, this, [this] {
            if (m_wallet) {
                m_wallet->deleteLater();
                m_wallet.clear();
            }
        });
    }

    void processPending()
    {
        if (m_pending.isEmpty()) {
            return;
        }

        const qint64 now = QDateTime::currentSecsSinceEpoch();
        const int secondsLeft = Totp::Period - int(now % Totp::Period);
        if (secondsLeft < MinSecondsLeft) {
            QTimer::singleShot(secondsLeft * 1000 + 300, this, &TotpSecretAgent::ensureWallet);
            return;
        }

        const QList<Request> requests = std::exchange(m_pending, {});
        for (const Request &req : requests) {
            answer(req, now);
        }
    }

    void answer(const Request &req, qint64 now)
    {
        QString password;
        QString seed;
        if (!m_wallet->hasFolder(WalletFolder) || !m_wallet->setFolder(WalletFolder)
            || m_wallet->readPassword(req.uuid + QStringLiteral(";password"), password) != 0
            || m_wallet->readPassword(req.uuid + QStringLiteral(";totp"), seed) != 0 || password.isEmpty() || seed.isEmpty()) {
            decline(req.msg, QStringLiteral("No TOTP entry for this connection"));
            return;
        }

        const QByteArray key = Totp::base32Decode(seed);
        if (key.isEmpty()) {
            qCWarning(VPNTOTP) << "TOTP secret for" << req.id << "is not valid base32";
            decline(req.msg, QStringLiteral("Invalid TOTP secret"));
            return;
        }

        NMStringMap secrets;
        secrets.insert(QStringLiteral("password"), password + Totp::code(key, now));
        NMVariantMapMap result;
        result.insert(req.setting, QVariantMap{{QStringLiteral("secrets"), QVariant::fromValue(secrets)}});

        m_bus.send(req.msg.createReply(QVariant::fromValue(result)));
        qCInfo(VPNTOTP) << "Supplied password + TOTP for" << req.id;
    }

    void failAll(const QString &why)
    {
        qCWarning(VPNTOTP) << why;
        const QList<Request> requests = std::exchange(m_pending, {});
        for (const Request &req : requests) {
            decline(req.msg, why);
        }
    }

    QDBusConnection m_bus;
    QPointer<KWallet::Wallet> m_wallet;
    QList<Request> m_pending;
};

class VpnTotpModule : public KDEDModule
{
    Q_OBJECT
public:
    VpnTotpModule(QObject *parent, const QVariantList &)
        : KDEDModule(parent)
        , m_agent(new TotpSecretAgent(this))
    {
    }

private:
    TotpSecretAgent *m_agent;
};

K_PLUGIN_CLASS_WITH_JSON(VpnTotpModule, "vpntotp.json")

#include "vpntotp.moc"
