#pragma once

#include <QByteArray>
#include <QString>

namespace Totp
{
// RFC 4648 base32 (spaces, dashes, padding and case are ignored). Empty on invalid input.
QByteArray base32Decode(const QString &input);

// RFC 6238 TOTP: HMAC-SHA1, 30 s period, 6 digits.
QString code(const QByteArray &key, qint64 unixTime);

inline constexpr int Period = 30;
}
