/*
 *  sysPass-Authenticator
 *
 * @author nuxsmin
 * @link http://syspass.org
 * @copyright 2012-2017, Rubén Domínguez nuxsmin@syspass.org
 *
 * This file is part of sysPass-Authenticator.
 *
 * sysPass-Authenticator is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * sysPass-Authenticator is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with sysPass-Authenticator. If not, see <http://www.gnu.org/licenses/>.
 */

sysPass.Plugins.Authenticator = function (Common) {
    "use strict";

    const ajaxUrl = "/index.php";
    const log = Common.log;
    const twofa = {
        check: function ($obj) {
            log.info("Authenticator:twofa:check");

            const opts = sysPassApp.requests.getRequestOpts();
            opts.url = ajaxUrl + "?r=" + $obj.data("action-route") + "/" + $obj.data("item-id");
            opts.data = $obj.serialize();

            sysPassApp.requests.getActionCall(opts, function (json) {
                sysPassApp.msg.out(json);

                if (json.status === 0) {
                    if (json.data.url !== undefined) {
                        setTimeout(function () {
                            sysPassApp.util.redirect(json.data.url);
                        }, 1000);
                    }
                }

                document.querySelector('.mdl-js-checkbox').MaterialCheckbox.uncheck();
                $obj.find("#pin").val('');
            });
        },
        save: function ($obj) {
            log.info("Authenticator:twofa:save");

            sysPassApp.actions.user.saveSettings($obj);
        },
        viewRecoveryCodes: function ($obj) {
            log.info("Authenticator:twofa:viewRecoveryCodes");

            const opts = sysPassApp.requests.getRequestOpts();
            opts.url = ajaxUrl + "?r=" + $obj.data("action-route");
            opts.data = {
                r: $obj.data("action-route") + "/" + $obj.data("item-id"),
                sk: sysPassApp.sk.get(),
                isAjax: 1
            };

            sysPassApp.requests.getActionCall(opts, function (json) {
                if (json.status === 0) {
                    const $results = $($obj.data("dst-id"));
                    $results.find(".list-wrap").html(sysPassApp.theme.html.getList(json.data, "vpn_key"));
                    $results.show("slow");
                } else {
                    Common.msg.out(json);
                }
            });
        }
    };

    /**
     * Comprobar la versión más reciente
     */
    const checkVersion = function () {
        log.info("Authenticator:checkVersion");

        const opts = sysPassApp.requests.getRequestOpts();
        opts.url = ajaxUrl + "?r=authenticator/checkVersion";
        opts.useLoading = false;
        opts.data = {
            sk: Common.sk.get()
        };

        return sysPassApp.requests.getActionCall(opts);
    };

    const init = function () {
    };

    init();

    return {
        twofa: twofa,
        checkVersion: checkVersion
    };
};
