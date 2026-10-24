<?php

namespace OPNsense\SSO\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\SSO\SessionSweeperJob;

/**
 * Schedule the session sweeper. Configurations that ran the first version of this
 * migration never got the job (issue #12); M1_0_5 repairs those.
 */
class M1_0_2 extends BaseModelMigration
{
    public function run($model)
    {
        SessionSweeperJob::ensure();
        parent::run($model);
    }
}
