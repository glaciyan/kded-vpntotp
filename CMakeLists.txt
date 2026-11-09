cmake_minimum_required(VERSION 3.20)
project(kded-vpntotp VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(ECM 6.0 REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})

include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDECompilerSettings NO_POLICY_SCOPE)

find_package(Qt6 6.6 REQUIRED COMPONENTS Core DBus)
find_package(KF6 6.0 REQUIRED COMPONENTS CoreAddons DBusAddons Wallet NetworkManagerQt)

kcoreaddons_add_plugin(vpntotp
    SOURCES src/vpntotp.cpp src/totp.cpp
    INSTALL_NAMESPACE "kf6/kded")

target_link_libraries(vpntotp PRIVATE
    Qt6::Core Qt6::DBus
    KF6::CoreAddons KF6::DBusAddons KF6::Wallet KF6::NetworkManagerQt)
