#include "totp.h"

#include <QCryptographicHash>
#include <QMessageAuthenticationCode>

namespace Totp
{
QByteArray base32Decode(const QString &input)
{
    QByteArray out;
    quint32 buffer = 0;
    int bits = 0;
    for (const QChar qc : input) {
        const char16_t c = qc.toUpper().unicode();
        int value;
        if (c >= u'A' && c <= u'Z') {
            value = c - u'A';
        } else if (c >= u'2' && c <= u'7') {
            value = c - u'2' + 26;
        } else if (c == u' ' || c == u'-' || c == u'=' || c == u'\t' || c == u'\n' || c == u'\r') {
            continue;
        } else {
            return {};
        }
        buffer = (buffer << 5) | quint32(value);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.append(char((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

QString code(const QByteArray &key, qint64 unixTime)
{
    quint64 counter = quint64(unixTime / Period);
    QByteArray msg(8, '\0');
    for (int i = 7; i >= 0; --i) {
        msg[i] = char(counter & 0xFF);
        counter >>= 8;
    }

    const QByteArray mac = QMessageAuthenticationCode::hash(msg, key, QCryptographicHash::Sha1);
    const int offset = quint8(mac.at(mac.size() - 1)) & 0x0F;
    const quint32 binary = (quint32(quint8(mac.at(offset)) & 0x7F) << 24) //
        | (quint32(quint8(mac.at(offset + 1))) << 16) //
        | (quint32(quint8(mac.at(offset + 2))) << 8) //
        | quint32(quint8(mac.at(offset + 3)));

    return QString::number(binary % 1000000).rightJustified(6, u'0');
}
}
