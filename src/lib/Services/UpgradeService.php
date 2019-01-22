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

namespace SP\Modules\Web\Plugins\Authenticator\Services;

use SP\Modules\Web\Plugins\Authenticator\Models\AuthenticatorData;
use SP\Plugin\PluginOperation;
use SP\Repositories\Plugin\PluginModel;
use SP\Util\Util;

/**
 * Class UpgradeService
 *
 * @package SP\Modules\Web\Plugins\Authenticator\Services
 */
final class UpgradeService
{
    /**
     * @var PluginOperation
     */
    private $pluginOperation;

    /**
     * UpgradeService constructor.
     *
     * @param PluginOperation $pluginOperation
     */
    public function __construct(PluginOperation $pluginOperation)
    {
        $this->pluginOperation = $pluginOperation;
    }

    /**
     * @param mixed $data
     *
     * @throws AuthenticatorException
     */
    public function upgrade_310_19012201($data)
    {
        if ($data instanceof PluginModel) {
            /** @var AuthenticatorData[] $authenticatorData */
            $authenticatorData = Util::unserialize(AuthenticatorData::class, $data->getData());

            if ($authenticatorData !== null) {
                foreach ($authenticatorData as $item) {
                    try {
                        $this->pluginOperation->create($item->getUserId(), $item);
                    } catch (\Exception $e) {
                        processException($e);
                    }
                }
            }
        } else {
            throw new AuthenticatorException('Unexpected data on upgrading');
        }
    }
}