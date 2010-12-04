<?php
/**
 * Superclass that has methods for testing OpenID stores. Subclass this to
 * test your own store implementation.
 *
 * @package OpenID
 */
abstract class Tests_Auth_OpenID_Store extends PHPUnit_TestCase {

    function pass() {}

    /**
     * Prepares for the SQL store tests.
     */
    function setUp()
    {
        $this->letters = \Auth\OpenID\letters;
        $this->digits  = \Auth\OpenID\digits;
        $this->punct   = \Auth\OpenID\punct;
        
        $this->allowed_nonce  = $this->letters . $this->digits;
        $this->allowed_handle = $this->letters . $this->digits . $this->punct;
    }

    /**
     * Generates an association with the specified parameters.
     */
    function genAssoc($now, $issued = 0, $lifetime = 600)
    {
        $sec = \Auth\OpenID\CryptUtil::randomString(20);
        $hdl = \Auth\OpenID\CryptUtil::randomString(128, $this->allowed_handle);
        return new \Auth\OpenID\Association(
            $hdl,
            $sec,
            $now + $issued,
            $lifetime,
            'HMAC-SHA1'
        );
    }

    /**
     * @access private
     */
    private function _checkRetrieve($store, $url, $handle, $expected, $name = null)
    {
        $retrieved_assoc = $store->getAssociation($url, $handle);
        if ($expected === null) {
            $this->assertTrue($retrieved_assoc === null);
        } else {
            $this->assertTrue($expected->equal($retrieved_assoc), $name);
        }
    }

    private function _checkRemove($store, $url, $handle, $expected, $name = null)
    {
        $present = $store->removeAssociation($url, $handle);
        $this->assertTrue((!$expected && !$present) ||
                          ($expected && $present),
                          $name);
    }

    /**
     * Make sure a given store has a minimum of API compliance. Call
     * this function with an empty store.
     *
     * Raises AssertionError if the store does not work as expected.
     *
     * OpenIDStore -> NoneType
     * 
     * @param \Auth\OpenID\Store $store
     */
    private function _testStore(\Auth\OpenID\Store $store)
    {
        // Association functions
        $now = time();

        $server_url = 'http://www.myopenid.com/openid';

        $assoc = $this->genAssoc($now);

        $this->_checkRetrieve($store, $server_url, null, null,
            'Make sure that a missing association returns no result');

        $store->storeAssociation($server_url, $assoc);
        $this->_checkRetrieve($store, $server_url, null, $assoc,
            'Check that after storage, getting returns the same result');

        $this->_checkRetrieve($store, $server_url, null, $assoc,
            'more than once');

        $store->storeAssociation($server_url, $assoc);
        $this->_checkRetrieve($store, $server_url, null, $assoc,
            'Storing more than once has no ill effect');

        // Removing an association that does not exist returns not present
        $this->_checkRemove($store, $server_url, $assoc->handle . 'x', false,
                            "Remove nonexistent association (1)");

        // Removing an association that does not exist returns not present
        $this->_checkRemove($store, $server_url . 'x', $assoc->handle, false,
                            "Remove nonexistent association (2)");

        // Removing an association that is present returns present
        $this->_checkRemove($store, $server_url, $assoc->handle, true,
                            "Remove existent association");

        // but not present on subsequent calls
        $this->_checkRemove($store, $server_url, $assoc->handle, false,
                            "Remove nonexistent association after removal");

        // Put assoc back in the store
        $store->storeAssociation($server_url, $assoc);

        // More recent and expires after assoc
        $assoc2 = $this->genAssoc($now, $issued = 1);
        $store->storeAssociation($server_url, $assoc2);

        $this->_checkRetrieve($store, $server_url, null, $assoc2,
            'After storing an association with a different handle, but the
same $server_url, the handle with the later expiration is
returned.');

        $this->_checkRetrieve($store, $server_url, $assoc->handle, $assoc,
            'We can still retrieve the older association');

        $this->_checkRetrieve($store, $server_url, $assoc2->handle, $assoc2,
            'Plus we can retrieve the association with the later expiration
explicitly');

        $assoc3 = $this->genAssoc($now, $issued = 2, $lifetime = 100);
        $store->storeAssociation($server_url, $assoc3);

        // More recent issued time, so assoc3 is expected.
        $this->_checkRetrieve($store, $server_url, null, $assoc3, "(1)");

        $this->_checkRetrieve($store, $server_url, $assoc->handle,
                              $assoc, "(2)");

        $this->_checkRetrieve($store, $server_url, $assoc2->handle,
                              $assoc2, "(3)");

        $this->_checkRetrieve($store, $server_url, $assoc3->handle,
                              $assoc3, "(4)");

        $this->_checkRemove($store, $server_url, $assoc2->handle, true, "(5)");

        $this->_checkRetrieve($store, $server_url, null, $assoc3, "(6)");

        $this->_checkRetrieve($store, $server_url, $assoc->handle,
                              $assoc, "(7)");

        $this->_checkRetrieve($store, $server_url, $assoc2->handle,
                              null, "(8)");

        $this->_checkRetrieve($store, $server_url, $assoc3->handle,
                              $assoc3, "(9)");

        $this->_checkRemove($store, $server_url, $assoc2->handle,
                            false, "(10)");

        $this->_checkRemove($store, $server_url, $assoc3->handle,
                            true, "(11)");

        $this->_checkRetrieve($store, $server_url, null, $assoc, "(12)");

        $this->_checkRetrieve($store, $server_url, $assoc->handle,
                              $assoc, "(13)");

        $this->_checkRetrieve($store, $server_url, $assoc2->handle,
                              null, "(14)");

        $this->_checkRetrieve($store, $server_url, $assoc3->handle,
                              null, "(15)");

        $this->_checkRemove($store, $server_url, $assoc2->handle,
                            false, "(16)");

        $this->_checkRemove($store, $server_url, $assoc->handle,
                            true, "(17)");

        $this->_checkRemove($store, $server_url, $assoc3->handle,
                            false, "(18)");

        $this->_checkRetrieve($store, $server_url, null, null, "(19)");

        $this->_checkRetrieve($store, $server_url, $assoc->handle,
                              null, "(20)");

        $this->_checkRetrieve($store, $server_url, $assoc2->handle,
                              null, "(21)");

        $this->_checkRetrieve($store, $server_url,$assoc3->handle,
                              null, "(22)");

        $this->_checkRemove($store, $server_url, $assoc2->handle,
                            false, "(23)");

        $this->_checkRemove($store, $server_url, $assoc->handle,
                            false, "(24)");

        $this->_checkRemove($store, $server_url, $assoc3->handle,
                            false, "(25)");

        // Put associations into store, for two different server URLs
        $assoc1 = $this->genAssoc($now);
        $assoc2 = $this->genAssoc($now + 2);
        $server_url1 = "http://one.example.com/one";
        $server_url2 = "http://two.localhost.localdomain/two";

        $store->storeAssociation($server_url1, $assoc1);
        $store->storeAssociation($server_url2, $assoc2);

        // Ask for each one, make sure we get it
        $this->_checkRetrieve($store, $server_url1, $assoc1->handle,
                              $assoc1, "(26)");

        $this->_checkRetrieve($store, $server_url2, $assoc2->handle,
                              $assoc2, "(27)");

        $store->storeAssociation($server_url1, $assoc1);
        $store->storeAssociation($server_url2, $assoc2);

        // Ask for each one, make sure we get it
        $this->_checkRetrieve($store, $server_url1, null,
                              $assoc1, "(28)");

        $this->_checkRetrieve($store, $server_url2, null,
                              $assoc2, "(29)");

        // test expired associations
        // assoc 1: server 1, valid
        // assoc 2: server 1, expired
        // assoc 3: server 2, expired
        // assoc 4: server 3, valid
        $assocValid1 = $this->genAssoc($now, -3600, 7200);
        $assocValid2 = $this->genAssoc($now, -5);
        $assocExpired1 = $this->genAssoc($now, -7200, 3600);
        $assocExpired2 = $this->genAssoc($now, -7200, 3600);

        if (!$store->supportsCleanup()) {
            return;
        }

        $store->cleanupAssociations();
        $store->storeAssociation($server_url . '1', $assocValid1);
        $store->storeAssociation($server_url . '1', $assocExpired1);
        $store->storeAssociation($server_url . '2', $assocExpired2);
        $store->storeAssociation($server_url . '3', $assocValid2);

        $cleaned = $store->cleanupAssociations();
        $this->assertEquals(2, $cleaned);
    }

    private function _checkUseNonce($store, $nonce, $expected, $server_url, $msg=null)
    {
        list($stamp, $salt) = \Auth\OpenID\splitNonce($nonce);
        $actual = $store->useNonce($server_url, $stamp, $salt);
        $this->assertEquals(intval($expected), intval($actual), "_checkUseNonce failed: $server_url, $msg");
    }

    private function _testNonce($store)
    {
        // Nonce functions

        $server_url = 'http://www.myopenid.com/openid';

        foreach (array($server_url, '') as $url) {
            // Random nonce (not in store)
            $nonce1 = \Auth\OpenID\mkNonce();

            // A nonce is not by default
            $this->_checkUseNonce($store, $nonce1, true, $url, "blergx");

            // Once stored, cannot be stored again
            $this->_checkUseNonce($store, $nonce1, false, $url, 2);

            // And using again has the same effect
            $this->_checkUseNonce($store, $nonce1, false, $url, 3);

            // Nonces from when the universe was an hour old should
            // not pass these days.
            $old_nonce = \Auth\OpenID\mkNonce(3600);
            $this->_checkUseNonce($store, $old_nonce, false, $url,
                                  "Old nonce ($old_nonce) passed.");

        }
    }

    private function _testNonceCleanup($store) {
        if (!$store->supportsCleanup()) {
        	return;
        }

        $server_url = 'http://www.myopenid.com/openid';

        $now = time();

        $old_nonce1 = \Auth\OpenID\mkNonce($now - 20000);
        $old_nonce2 = \Auth\OpenID\mkNonce($now - 10000);
        $recent_nonce = \Auth\OpenID\mkNonce($now - 600);

        global $Auth_OpenID_SKEW;
        $orig_skew = $Auth_OpenID_SKEW;

        $Auth_OpenID_SKEW = 0;
        $store->cleanupNonces();
        // Set SKEW high so stores will keep our nonces.
        $Auth_OpenID_SKEW = 100000;

        $params = \Auth\OpenID\splitNonce($old_nonce1);
        array_unshift($params, $server_url);
        $this->assertTrue(call_user_func_array(array($store, 'useNonce'), $params));

        $params = \Auth\OpenID\splitNonce($old_nonce2);
        array_unshift($params, $server_url);
        $this->assertTrue(call_user_func_array(array($store, 'useNonce'), $params));

        $params = \Auth\OpenID\splitNonce($recent_nonce);
        array_unshift($params, $server_url);
        $this->assertTrue(call_user_func_array(array($store, 'useNonce'), $params));

        $Auth_OpenID_SKEW = 3600;
        $cleaned = $store->cleanupNonces();
        $this->assertEquals(2, $cleaned); // , "Cleaned %r nonces." % (cleaned,)

        $Auth_OpenID_SKEW = 100000;
        // A roundabout method of checking that the old nonces were
        // cleaned is to see if we're allowed to add them again.

        $params = \Auth\OpenID\splitNonce($old_nonce1);
        array_unshift($params, $server_url);
        $this->assertTrue(call_user_func_array(array($store, 'useNonce'), $params));
        $params = \Auth\OpenID\splitNonce($old_nonce2);
        array_unshift($params, $server_url);
        $this->assertTrue(call_user_func_array(array($store, 'useNonce'), $params));

        // The recent nonce wasn't cleaned, so it should still fail.
        $params = \Auth\OpenID\splitNonce($recent_nonce);
        array_unshift($params, $server_url);
        $this->assertFalse(call_user_func_array(array($store, 'useNonce'), $params));

        $Auth_OpenID_SKEW = $orig_skew;
    }

}
