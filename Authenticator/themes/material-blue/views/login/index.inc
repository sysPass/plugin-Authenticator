<?php /** @var \SP\Core\UI\ThemeIcons $icons */ ?>
<div id="actions" class="authenticator-2fa" align="center">
    <div id="box-2fa" class="box-form">
        <form id="frmLogin2fa" action="" method="post" class="form-action"
              data-onsubmit="twofa/check"
              data-plugin="Authenticator"
              data-action-route="<?php echo $route; ?>"
              data-hash="">
            <fieldset id="resetdata">
                <legend><?php echo _t('authenticator', 'Autentificación en 2 pasos'); ?></legend>
                <div class="mdl-textfield mdl-js-textfield mdl-textfield--floating-label">
                    <input id="pin" name="pin" type="text"
                           pattern="([0-9]{6}|[0-9a-f]{20})" class="mdl-textfield__input mdl-color-text--indigo-400"
                           maxlength="20"/>
                    <label class="mdl-textfield__label"
                           for="pin"><?php echo _t('authenticator', 'Introducir código'); ?></label>
                </div>

                <label class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect" for="code_reset">
                    <input type="checkbox" name="code_reset" id="code_reset" class="mdl-checkbox__input">
                    <span class="mdl-checkbox__label"><?php echo _t('authenticator', 'Olvidé mi código'); ?></span>
                </label>

                <?php if (isset($from, $from_hash)): ?>
                    <input type="hidden" name="from" value="<?php echo $from; ?>"/>
                    <input type="hidden" name="h" value="<?php echo $from_hash; ?>"/>
                <?php endif; ?>

                <input type="hidden" name="sk" value=""/>
                <input type="hidden" name="isAjax" value="1"/>
            </fieldset>

            <div class="buttons">
                <button id="btnBack" type="button"
                        class="mdl-button mdl-js-button mdl-button--raised mdl-button--primary">
                    <i class="material-icons"
                       title="<?php echo _t('authenticator', 'Volver a iniciar sesión'); ?>">
                        <?php echo $icons->getIconBack()->getIcon(); ?></i>
                    <?php echo _t('authenticator', 'Volver'); ?>
                </button>

                <button id="btnLogin" class="mdl-button mdl-js-button mdl-button--raised mdl-button--primary">
                    <?php echo _t('authenticator', 'Acceder'); ?>
                    <i class="material-icons"
                       title="<?php echo _t('authenticator', 'Solicitar'); ?>"><?php echo $icons->getIconPlay()->getIcon(); ?></i>
                </button>
            </div>
        </form>
    </div>
</div>
