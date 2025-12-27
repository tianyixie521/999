[app]

title = SOCKS5 Tester
package.name = socks5tester
package.domain = org.example

source.dir = .
source.include_exts = py,png,jpg,kv,ttf

version = 0.1.0

requirements = python3,kivy

orientation = portrait
fullscreen = 0

android.permissions = INTERNET
android.minapi = 21
android.archs = arm64-v8a,armeabi-v7a

[buildozer]
log_level = 2
warn_on_root = 1
