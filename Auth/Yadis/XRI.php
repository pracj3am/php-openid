<?php
namespace Auth\Yadis;
/**
 * Routines for XRI resolution.
 *
 * @package OpenID
 * @author JanRain, Inc. <openid@janrain.com>
 * @copyright 2005-2008 Janrain, Inc.
 * @license http://www.apache.org/licenses/LICENSE-2.0 Apache
 */

require_once 'Auth/Yadis/Misc.php';
require_once 'Auth/Yadis/Yadis.php';
require_once 'Auth/OpenID.php';

function getDefaultProxy()
{
    return 'http://xri.net/';
}

function getXRIAuthorities()
{
    return array('!', '=', '@', '+', '$', '(');
}

function getEscapeRE()
{
    $parts = array();
    foreach (array_merge(getUCSChars(),
                         getIPrivateChars()) as $pair) {
        list($m, $n) = $pair;
        $parts[] = sprintf("%s-%s", chr($m), chr($n));
    }

    return sprintf('/[%s]/', implode('', $parts));
}

function getXrefRE()
{
    return '/\((.*?)\)/';
}

function identifierScheme($identifier)
{
    if (startswith($identifier, 'xri://') ||
        ($identifier &&
          in_array($identifier[0], getXRIAuthorities()))) {
        return "XRI";
    } else {
        return "URI";
    }
}

function toIRINormal($xri)
{
    if (!startswith($xri, 'xri://')) {
        $xri = 'xri://' . $xri;
    }

    return escapeForIRI($xri);
}

function _escape_xref($xref_match)
{
    $xref = $xref_match[0];
    $xref = str_replace('/', '%2F', $xref);
    $xref = str_replace('?', '%3F', $xref);
    $xref = str_replace('#', '%23', $xref);
    return $xref;
}

function escapeForIRI($xri)
{
    $xri = str_replace('%', '%25', $xri);
    $xri = preg_replace_callback(getXrefRE(),
                                 '\Auth\Yadis\_escape_xref', $xri);
    return $xri;
}

function toURINormal($xri)
{
    return iriToURI(toIRINormal($xri));
}

function iriToURI($iri)
{
    if (1) {
        return $iri;
    } else {
        // According to RFC 3987, section 3.1, "Mapping of IRIs to URIs"
        return preg_replace_callback(getEscapeRE(),
                                     '\Auth\Yadis\pct_escape_unicode', $iri);
    }
}


function XRIAppendArgs($url, $args)
{
    // Append some arguments to an HTTP query.  Yes, this is just like
    // OpenID's appendArgs, but with special seasoning for XRI
    // queries.

    if (count($args) == 0) {
        return $url;
    }

    // Non-empty array; if it is an array of arrays, use multisort;
    // otherwise use sort.
    if (array_key_exists(0, $args) &&
        is_array($args[0])) {
        // Do nothing here.
    } else {
        $keys = array_keys($args);
        sort($keys);
        $new_args = array();
        foreach ($keys as $key) {
            $new_args[] = array($key, $args[$key]);
        }
        $args = $new_args;
    }

    // According to XRI Resolution section "QXRI query parameters":
    //
    // "If the original QXRI had a null query component (only a
    //  leading question mark), or a query component consisting of
    //  only question marks, one additional leading question mark MUST
    //  be added when adding any XRI resolution parameters."
    if (strpos(rtrim($url, '?'), '?') !== false) {
        $sep = '&';
    } else {
        $sep = '?';
    }

    return $url . $sep . \Auth\OpenID::httpBuildQuery($args);
}

function providerIsAuthoritative($providerID, $canonicalID)
{
    $lastbang = strrpos($canonicalID, '!');
    $p = substr($canonicalID, 0, $lastbang);
    return $p == $providerID;
}

function rootAuthority($xri)
{
    // Return the root authority for an XRI.

    $root = null;

    if (startswith($xri, 'xri://')) {
        $xri = substr($xri, 6);
    }

    $authority = explode('/', $xri, 2);
    $authority = $authority[0];
    if ($authority[0] == '(') {
        // Cross-reference.
        // XXX: This is incorrect if someone nests cross-references so
        //   there is another close-paren in there.  Hopefully nobody
        //   does that before we have a real xriparse function.
        //   Hopefully nobody does that *ever*.
        $root = substr($authority, 0, strpos($authority, ')') + 1);
    } else if (in_array($authority[0], getXRIAuthorities())) {
        // Other XRI reference.
        $root = $authority[0];
    } else {
        // IRI reference.
        $_segments = explode("!", $authority);
        $segments = array();
        foreach ($_segments as $s) {
            $segments = array_merge($segments, explode("*", $s));
        }
        $root = $segments[0];
    }

    return XRI($root);
}

function XRI($xri)
{
    if (!startswith($xri, 'xri://')) {
        $xri = 'xri://' . $xri;
    }
    return $xri;
}

function getCanonicalID($iname, $xrds)
{
    // Returns false or a canonical ID value.

    // Now nodes are in reverse order.
    $xrd_list = array_reverse($xrds->allXrdNodes);
    $parser = $xrds->parser;
    $node = $xrd_list[0];

    $canonicalID_nodes = $parser->evalXPath('xrd:CanonicalID', $node);

    if (!$canonicalID_nodes) {
        return false;
    }

    $canonicalID = $canonicalID_nodes[0];
    $canonicalID = XRI($parser->content($canonicalID));

    $childID = $canonicalID;

    for ($i = 1; $i < count($xrd_list); $i++) {
        $xrd = $xrd_list[$i];

        $parent_sought = substr($childID, 0, strrpos($childID, '!'));
        $parentCID = $parser->evalXPath('xrd:CanonicalID', $xrd);
        if (!$parentCID) {
            return false;
        }
        $parentCID = XRI($parser->content($parentCID[0]));

        if (strcasecmp($parent_sought, $parentCID)) {
            // raise XRDSFraud.
            return false;
        }

        $childID = $parent_sought;
    }

    $root = rootAuthority($iname);
    if (!providerIsAuthoritative($root, $childID)) {
        // raise XRDSFraud.
        return false;
    }

    return $canonicalID;
}


