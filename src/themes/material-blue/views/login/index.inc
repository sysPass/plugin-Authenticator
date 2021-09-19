<?php
/**
 * @var \SP\Core\UI\ThemeIcons $icons
 * @var \SP\Config\ConfigData  $configData
 * @var callable               $_getvar
 * @var \SP\Mvc\View\Template  $this
 */
?>
<div id="actions" class="authenticator-2fa" align="center">
    <div id="box-2fa" class="box-form">
        <form id="frmLogin2fa" action="" method="post" class="form-action"
              data-onsubmit="twofa/check"
              data-plugin="Authenticator"
              data-action-route="<?php echo $_getvar('route'); ?>"
              data-hash="">
            <fieldset id="resetdata">
                <legend><?php echo _t('authenticator', 'Autenticação de dois fatores'); ?></legend>
                <div class="mdl-textfield mdl-js-textfield mdl-textfield--floating-label">
                    <input id="pin" name="pin" type="text"
                           pattern="([0-9]{6}|[0-9a-f]{20})"
                           class="mdl-textfield__input mdl-color-text--indigo-400"
                           maxlength="20"/>
                    <label class="mdl-textfield__label"
                           for="pin"><?php echo _t('authenticator', 'Introduza o código'); ?></label>
                </div>

                <?php if ($_getvar('isMailEnabled')): ?>
                    <label class="mdl-checkbox mdl-js-checkbox mdl-js-ripple-effect"
                           for="code_reset">
                        <input type="checkbox" name="code_reset" id="code_reset"
                               class="mdl-checkbox__input">
                        <span class="mdl-checkbox__label"><?php echo _t('authenticator', 'Esqueci-me do meu código'); ?></span>

                        <div id="help-2fa"
                             class="icon material-icons <?php echo $icons->getIconHelp()->getClass(); ?>"><?php echo $icons->getIconHelp()->getIcon(); ?></div>
                    </label>


                    <div class="mdl-tooltip mdl-tooltip--large" for="help-2fa">
                        <p>
                            <?php echo _t('authenticator', 'Um e-mal foi enviado com o código de recuperação\'introduza o código, apenas click em "Iniciar sessão".'); ?>
                        </p>

                        <p>
                            <?php echo _t('authenticator', sprintf('Se não houver qualquer código de recuperação restante, terá que esperar %dh por novos códigos', $_getvar('recoveryGraceTime'))); ?>
                        </p>
                    </div>
                <?php endif; ?>

                <?php if ($_getvar('from') && $_getvar('from_hash')): ?>
                    <input type="hidden" name="from"
                           value="<?php echo $_getvar('from'); ?>"/>
                    <input type="hidden" name="h"
                           value="<?php echo $_getvar('from_hash'); ?>"/>
                <?php endif; ?>

                <input type="hidden" name="sk" value=""/>
                <input type="hidden" name="isAjax" value="1"/>
            </fieldset>

            <div class="buttons">
                <button id="btnBack" type="button"
                        class="mdl-button mdl-js-button mdl-button--raised mdl-button--primary">
                    <i class="material-icons"
                       title="<?php echo _t('authenticator', 'Voltar para iniciar sessão'); ?>">
                        <?php echo $icons->getIconBack()->getIcon(); ?></i>
                    <?php echo _t('authenticator', 'Voltar'); ?>
                </button>

                <button id="btnLogin"
                        class="mdl-button mdl-js-button mdl-button--raised mdl-button--primary">
                    <?php echo _t('authenticator', 'Iniciar sessão'); ?>
                    <i class="material-icons"
                       title="<?php echo _t('authenticator', 'Solicitação'); ?>"><?php echo $icons->getIconPlay()->getIcon(); ?></i>
                </button>
            </div>
        </form>
    </div>
</div>
