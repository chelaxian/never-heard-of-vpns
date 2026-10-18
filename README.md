# NeverHeardOfVPNs
**Jailbreak tweak to bypass local VPN checks in iOS applications**

## Building
You need to have [Theos](https://theos.dev/docs/installation) installed.

### Rootless
To build this tweak for iOS devices on rootless jailbreaks, run the following command:
```
make package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless
```

### Rootful
To build this tweak for iOS devices on rootful jailbreaks, run the following command:
```
make package FINALPACKAGE=1
```
## Изменения ratu.sh от 2026-10-18 (версия 1.1.0)

Адаптация исходного NeverHeardOfVPNs 1.0.1, автор thatmarcel. Лицензия AGPL-3.0; полный исходный код, сборка и проверки находятся в этой ветке.

Пакет предназначен для iOS 17.0–26.0.1 **при наличии совместимого rootless jailbreak и внедрения твиков**. Это диапазон метаданных и используемых API, а не заявление о наличии jailbreak для каждой версии iOS. Проверка на физическом устройстве выполняется отдельно; iOS 26 не проверена.

- Фильтрация `utun`, `ipsec`, `ppp`, `tun`, `tap` с любым числовым суффиксом.
- `CFNetworkCopySystemProxySettings`: удаляются только туннели из `__SCOPED__`, прочие настройки прокси/PAC сохраняются; сетевые данные не пишутся в журнал.
- `getifaddrs` / `freeifaddrs` и `if_nameindex` / `if_freenameindex`: фильтрация с сохранением исходных выделений памяти до парного освобождения.
- `nw_path_enumerate_interfaces`: скрываются интерфейсы с туннельными именами. `nw_path_uses_interface_type(other)` скрывается только при обнаруженном туннеле и отсутствии другого видимого интерфейса такого типа. Wi-Fi, cellular, status и маршрут не подменяются.
- Обработка только сторонних приложений `.app`. Системные приложения, расширения, демоны и приложения с собственным NetworkExtension-провайдером исключены, чтобы не нарушать работу VPN. Для другого VPN-клиента отключите этот твик в Choicy.
- После обновления полностью закройте и откройте нужное приложение. Отдельных настроек нет. Для исключения приложения используйте Choicy.

### Границы скрытия

Универсальной гарантии для всех приложений нет. Внешний IP, ASN, репутация VPN-сервера и геолокация видны удалённому серверу; подмена локальных API их не меняет. Прямые `sysctl`/route/ioctl-запросы, приватные NetworkExtension API, адреса сокетов и приложения с отключённым внедрением могут обнаруживать VPN другими способами. Прямые проверки имени/индекса интерфейса также не перехватываются, чтобы не менять работу системного сетевого стека. Приложение с собственным VPN-расширением по умолчанию исключено.

### Проверки

`tests/sanitizer.mm`: сохранение прокси, граничные имена, туннель в начале/середине/конце списка, пустой результат, ошибки, парное освобождение и 8000 конкурентных циклов под AddressSanitizer/UndefinedBehaviorSanitizer на macOS. `tests/probe.mm`: отдельный диагностический инструмент для сравнения перечисления интерфейсов до/после загрузки твика на iOS; в DEB не входит. Полный результат физической проверки фиксируется в `VALIDATION.md`.
