<?php
/**
 * Class that tests all of the stores included with the OpenID library
 *
 * @package OpenID
 */
class Tests_Auth_OpenID_Included_StoreTest extends Tests_Auth_OpenID_Store {

    function test_memstore()
    {
        require_once 'Tests/Auth/OpenID/MemStore.php';
        $store = new Tests_Auth_OpenID_MemStore();
        $this->_testStore($store);
        $this->_testNonce($store);
        $this->_testNonceCleanup($store);
    }

    function test_filestore()
    {
        require_once 'Auth/OpenID/Store/File.php';

        $temp_dir = _Auth_OpenID_mkdtemp();

        if (!$temp_dir) {
            trigger_error('Could not create temporary directory ' .
                          'with Auth_OpenID_FileStore::_mkdtemp',
                          E_USER_WARNING);
            return null;
        }

        $store = new Auth_OpenID_Store_File($temp_dir);
        $this->_testStore($store);
        $this->_testNonce($store);
        $this->_testNonceCleanup($store);
        $store->destroy();
    }

    function test_postgresqlstore()
    {
        // If the postgres extension isn't loaded or loadable, succeed
        // because we can't run the test.
        if (!(extension_loaded('pgsql')) ||
            !(@include_once 'DB.php')) {
            $this->markTestSkipped("not testing PostGreSQL store");
            return;
        }

        require_once 'Auth/OpenID/Store/PostgreSQL.php';

        $temp_db_name = _Auth_OpenID_getTmpDbName();

        $connect_db_name = 'test_master';

        $dsn = array(
                     'phptype'  => 'pgsql',
                     'username' => 'openid_test',
                     'password' => '',
                     'hostspec' => $GLOBALS['_Auth_OpenID_db_test_host'],
                     'database' => $connect_db_name
                     );

        $allowed_failures = 5;
        $result = null;
        $sleep_time = 1.0;
        $sql = sprintf("CREATE DATABASE %s", $temp_db_name);

        for ($failures = 0; $failures < $allowed_failures; $failures++) {
            $template_db = DB::connect($dsn);

            if (PEAR::isError($template_db)) {
                $result = $template_db;
            } else {
                // Try to create the test database.
                $result = $template_db->query($sql);

                $template_db->disconnect();
                unset($template_db);

                if (!PEAR::isError($result)) {
                    break;
                }
            }

            $sleep_time *= ((mt_rand(1, 100) / 100.0) + 1.5);
            echo "Failed to create database $temp_db_name.\n"
                . "Waiting $sleep_time before trying again\n";

            $int_sleep = floor($sleep_time);
            $frac_sleep = $sleep_time - $int_sleep;
            sleep($int_sleep);
            usleep($frac_sleep * 1000000.0);
        }

        if ($failures == $allowed_failures) {
            $this->pass("Temporary database creation failed after $failures ".
                        " tries ('$temp_db_name'): " . $result->getMessage());
            return;
        }

        // Disconnect from template1 and reconnect to the temporary
        // testing database.
        $dsn['database'] = $temp_db_name;
        $db = DB::connect($dsn);

        if (PEAR::isError($db)) {
            $this->fail("Temporary database connection failed " .
                        " ('$temp_db_name'): " . $db->getMessage());
            return;
        }

        $store = new Auth_OpenID_Store_PostgreSQL($db);

        $this->assertFalse($store->tableExists($store->nonces_table_name));
        $this->assertFalse($store->tableExists($store->associations_table_name));

        $store->createTables();

        $this->assertTrue($store->tableExists($store->nonces_table_name));
        $this->assertTrue($store->tableExists($store->associations_table_name));

        $this->_testStore($store);
        $this->_testNonce($store);
        $this->_testNonceCleanup($store);

        $db->disconnect();
        unset($db);

        // Connect to template1 again so we can drop the temporary
        // database.
        $dsn['database'] = $connect_db_name;
        $template_db     = DB::connect($dsn);

        if (PEAR::isError($template_db)) {
            $this->fail("Template database connection (to drop " .
                        "temporary database) failed: " .
                        $template_db->getMessage());
            return;
        }

        $result = $template_db->query(sprintf("DROP DATABASE %s",
                                              $temp_db_name));

        if (PEAR::isError($result)) {
            $this->fail("Dropping temporary database failed: " .
                        $result->getMessage());
            return;
        }

        $template_db->disconnect();
        unset($template_db);
    }

    function test_sqlitestore()
    {
        // If the sqlite extension isn't loaded or loadable, succeed
        // because we can't run the test.
        if (!(extension_loaded('sqlite')) ||
            !(@include_once 'DB.php')) {
            $this->markTestSkipped("not testing SQLite store");
            return;
        }

        require_once 'Auth/OpenID/Store/SQLite.php';

        $temp_dir = _Auth_OpenID_mkdtemp();

        if (!$temp_dir) {
            $this->fail('Could not create temporary directory ' .
                'with Auth_OpenID_FileStore::_mkdtemp');
            return;
        }

        $dsn = 'sqlite:///' . urlencode($temp_dir) . '/php_openid_storetest.db';
        $db  = DB::connect($dsn);

        if (PEAR::isError($db)) {
            $this->fail("SQLite database connection failed: " .
                        $db->getMessage());
        } else {
            $store = new Auth_OpenID_Store_SQLite($db);
            $this->assertTrue($store->createTables(), "Table creation failed");
            $this->_testStore($store);
            $this->_testNonce($store);
            $this->_testNonceCleanup($store);
        }

        $db->disconnect();
        unset($db);
        unset($store);
        unlink($temp_dir . '/php_openid_storetest.db');
        rmdir($temp_dir);
    }

    function test_mysqlstore()
    {
        // If the mysql extension isn't loaded or loadable, succeed
        // because we can't run the test.
        if (!(extension_loaded('mysql')) ||
            !(@include_once 'DB.php')) {
            $this->markTestSkipped("not testing MySQL store");
            return;
        }

        require_once 'Auth/OpenID/Store/MySQL.php';

        $dsn = array(
            'phptype'  => 'mysql',
            'username' => 'openid_test',
            'password' => '',
            'hostspec' => $GLOBALS['_Auth_OpenID_db_test_host']
        );

        $db = DB::connect($dsn);

        if (PEAR::isError($db)) {
            $this->markTestSkipped("MySQL database connection failed: " .
                $db->getMessage());
            return;
        }

        $temp_db_name = _Auth_OpenID_getTmpDbName();

        $result = $db->query("CREATE DATABASE $temp_db_name");

        if (PEAR::isError($result)) {
            $this->fail("Error creating MySQL temporary database: " .
                $result->getMessage());
            return;
        }

        $db->query("USE $temp_db_name");

        $store = new Auth_OpenID_Store_MySQL($db);
        $store->createTables();
        $this->_testStore($store);
        $this->_testNonce($store);
        $this->_testNonceCleanup($store);

        $db->query("DROP DATABASE $temp_db_name");
    }

    function test_mdb2store()
    {
        // The MDB2 test can use any database engine. MySQL is chosen
        // arbitrarily.
        if (!(extension_loaded('mysql') ||
              @dl('mysql.' . PHP_SHLIB_SUFFIX)) ||
            !(@include_once 'MDB2.php')) {
            $this->markTestSkipped("not testing MDB2 store");
            return;
        }

        require_once 'Auth/OpenID/Store/MDB2.php';

        $dsn = array(
            'phptype'  => 'mysql',
            'username' => 'openid_test',
            'password' => '',
            'hostspec' => $GLOBALS['_Auth_OpenID_db_test_host']
        );

        
        $db = MDB2::connect($dsn);

        if (PEAR::isError($db)) {
            $this->fail("MySQL database connection failed: " .
                $db->getMessage());
            return;
        }

        $temp_db_name = _Auth_OpenID_getTmpDbName();

        $result = $db->query("CREATE DATABASE $temp_db_name");

        if (PEAR::isError($result)) {
            $this->pass("Error creating MySQL temporary database: " .
                $result->getMessage());
            return;
        }

        $db->query("USE $temp_db_name");

        $store = new Auth_OpenID_MDB2Store($db);
        if (!$store->createTables()) {
            $this->fail("Failed to create tables");
            return;
        }
        $this->_testStore($store);
        $this->_testNonce($store);
        $this->_testNonceCleanup($store);

        $db->query("DROP DATABASE $temp_db_name");
    }
}
