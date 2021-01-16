## sysPass Authenticator Plugin

---

Plugin to use two factor based authentication with applications that generate TOTP codes like Google Authenticator, AndOTP or KeepassXC

Please, select the correct branch in order to download a sysPass compatible version:

|sysPass version|Plugin's version|Branch|
|:-------------:|:--------------:|:----:|
|v3.2           |v2.2            |master &#x7c;&#x7c; v2.2|
|v3.0 <= v3.1   |v2.1            |v2.1|
|v2.0 < v3.0    |v1.0            |v1.0|

---

### v2 Installation

As told above, this version is only compatible with **sysPass v3** and it needs to be installed through **composer**.

Please select the installation method depending on the instance type:

* If you are running a **non-Docker** based instance:

```composer require syspass/plugin-authenticator:^v2.0```

* If you are running a **Docker** based instance, set `syspass/plugin-authenticator:^v2.0` value within an environment variable called `COMPOSER_EXTENSIONS`.
 
---

### v1 Installation

Please download the v1 branch files and unpack them into `.../inc/Plugins` directory.

---

https://syspass.org

https://demo.syspass.org

https://doc.syspass.org

https://github.com/sysPass/plugin-Authenticator
