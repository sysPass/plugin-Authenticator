<?php
/**
 * sysPass
 *
 * @author    nuxsmin
 * @link      https://syspass.org
 * @copyright 2012-2019, Rubén Domínguez nuxsmin@$syspass.org
 *
 * This file is part of sysPass.
 *
 * sysPass is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * sysPass is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *  along with sysPass.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace SP\Modules\Web\Plugins\Authenticator\Util;

use SP\Core\Context\ContextInterface;
use SP\Core\Context\SessionContext;
use SP\Modules\Web\Plugins\Authenticator\Models\AuthenticatorData;
use SP\Modules\Web\Plugins\Authenticator\Plugin;

/**
 * Class PluginContext
 *
 * @package Plugins\Authenticator
 */
class PluginContext
{
    const CONTEXT_KEY = 'plugin_' . Plugin::PLUGIN_NAME;
    const USERDATA = 'userdata';
    const TWOFA_PASS = 'twofapass';

    /**
     * @var SessionContext
     */
    private $context;

    /**
     * Session constructor.
     *
     * @param ContextInterface $context
     */
    public function __construct(ContextInterface $context)
    {
        $this->context = $context;
    }

    /**
     * Devolver los datos del usuario
     *
     * @return AuthenticatorData
     */
    public function getUserData(): AuthenticatorData
    {
        return $this->context->getPluginKey(self::CONTEXT_KEY, self::USERDATA);
    }

    /**
     * Devolver el estado de 2FA del usuario
     *
     * @return bool
     */
    public function getTwoFApass(): bool
    {
        return $this->context->getPluginKey(self::CONTEXT_KEY, self::TWOFA_PASS);
    }

    /**
     * Establecer los datos del usuario
     *
     * @param AuthenticatorData $data
     */
    public function setUserData(AuthenticatorData $data)
    {
        $this->context->setPluginKey(self::CONTEXT_KEY, self::USERDATA, $data);
    }

    /**
     * Establecer el estado de 2FA del usuario
     *
     * @param bool $pass
     */
    public function setTwoFApass(bool $pass)
    {
        $this->context->setPluginKey(self::CONTEXT_KEY, self::TWOFA_PASS, $pass);
    }
}