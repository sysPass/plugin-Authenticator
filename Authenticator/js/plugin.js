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

sysPass.Plugin.Authenticator = function (Common) {
    "use strict";

    var log = Common.log;
    var base = "/inc/Plugins/Authenticator";

    var twofa = {
        check: function ($obj) {
            log.info("Authenticator:twofa:check");

            var opts = Common.appRequests().getRequestOpts();
            opts.url = base + "/ajax/ajax_actions.php";
            opts.data = $obj.serialize();

            Common.appRequests().getActionCall(opts, function (json) {
                Common.msg.out(json);

                if (json.status === 0) {
                    setTimeout(function () {
                        Common.redirect("index.php");
                    }, 1000);
                }
            });
        },
        save: function ($obj) {
            log.info("Authenticator:twofa:save");

            var opts = Common.appRequests().getRequestOpts();
            opts.url = base + "/ajax/ajax_actions.php";
            opts.data = $obj.serialize();

            Common.appRequests().getActionCall(opts, function (json) {
                Common.msg.out(json);

                if (json.status === 0) {
                    Common.appActions().doAction({
                        actionId: $obj.data("nextaction-id"),
                        itemId: $obj.data("activetab")
                    });
                }
            });
        },
        viewRecoveryCodes: function ($obj) {
            log.info("Authenticator:twofa:viewRecoveryCodes");

            var opts = Common.appRequests().getRequestOpts();
            opts.url = base + "/ajax/ajax_actions.php";
            opts.data = {
                actionId: $obj.data("action-id"),
                sk: Common.sk.get()
            };

            Common.appRequests().getActionCall(opts, function (json) {
                if (json.status === 0) {
                    var $results = $($obj.data("dst-id"));
                    $results.find(".list-wrap").html(Common.appTheme().html.getList(json.data, "vpn_key"));
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
    var checkVersion = function () {
        log.info("Authenticator:checkVersion");

        var opts = Common.appRequests().getRequestOpts();
        opts.url = base + "/ajax/ajax_actions.php";
        opts.useLoading = false;
        opts.data = {
            actionId: 100,
            sk: Common.sk.get()
        };

        return Common.appRequests().getActionCall(opts);
    };

    var init = function () {

    };

    init();

    return {
        twofa: twofa,
        checkVersion: checkVersion
    };
};
