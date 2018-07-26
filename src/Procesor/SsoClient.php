<?php

namespace RazzTek\Processor;

class SsoClient {
    private $client;
    private $username;
    private $attributes;

    public function __construct($protocol = 'SAML_VERSION_1_1')
    {

    	$this->username = null;
    	$this->attributes = array();

		$initialized = \phpCAS::isInitialized();

		if(!$initialized) {
			require_once 'SsoConfig.php';
            $this->cas_host = $cas_host;
            $this->cas_port = $cas_port;
            $this->cas_context = $cas_context;
            $this->cas_server_ca_cert_path = $cas_server_ca_cert_path;
            $this->cas_debug_log = $cas_debug_log;


			//set which protocol CAS should use
			switch($protocol) {
				case 'CAS_VERSION_1_0':
					\phpCAS::client(CAS_VERSION_1_0, $this->cas_host, $this->cas_port, $this->cas_context, false);
                    			break;
				case 'CAS_VERSION_2_0':
					\phpCAS::client(CAS_VERSION_2_0, $this->cas_host, $this->cas_port, $this->cas_context, false);
					break;
				case 'SAML_VERSION_1_1':
				default:
					\phpCAS::client(SAML_VERSION_1_1, $this->cas_host, $this->cas_port, $this->cas_context, false);
			}

			\phpCAS::setCasServerCACert($this->cas_server_ca_cert_path);
		}

    }

    public function authenticate()
    {

		\phpCAS::forceAuthentication();

        $this->username = \phpCAS::getUser();

	    if (\phpCAS::hasAttributes()) {
            $this->attributes = \phpCAS::getAttributes();
        }

	    //debug set in config file
	    if (defined('SSO_DEBUG')) {
            \phpCAS::setDebug($this->cas_debug_log);
            \phpCAS::setVerbose(true);
        }

        return $this->credentials();


    }

    public function logout()
    {
	    \phpCAS::logout();
    }


    public function get_user()
    {
	    return $this->username;
    }

    public function get_attributes()
    {
	    return $this->attributes;
    }

    private function credentials()
    {
        $result = array();

        $result['username'] = $this->get_user();
        $result['attributes'] = $this->get_attributes();

        return $result;
    }
}
