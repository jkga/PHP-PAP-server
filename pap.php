<?php
/**
 *Personal Authentication Protocol library using PHP
 *This library is an implementation of PA Protocol in PHP
 *@package pap\Main
 *@author john kenneth abella <https://github.com/jkga>
*/
namespace pap;

class Main{
	private $__app_credentials;
	private $__app_salt; 
	private $__app_username;
	private $__app_password;
	protected $__app_body;
	protected $__app_header;
	protected $__app_id;
	protected $__app_session;
	protected $__app_token;
	protected $__app_key;
	protected $__app_expiration=0; #No expiration
	protected $__app_mode;
	static $TOKEN; #original token
	static $ID; #original ID
	static $GRANT=false; #default to non-grant option request
	static $CREDENTIALS;
	
	/*define variables as Object and read header request*/
	public function __construct(){
		$this->_body=new \stdClass; 
		self::$CREDENTIALS=new \stdClass;
		self::read_request_header(); 
		self::read_request_body();
	}


	/*use for parsing the request header*/
	private function read_request_header(){
		$__apache_header=apache_request_headers(); #apache
		$this->__app_header=@$__apache_header['X-PAP-Auth']; 
		if(isset($__apache_header['X-PAP-Content'])) $this->__app_header=$__apache_header['X-PAP-Content'];
		return $this;
	}



	/*use for parsing the request body*/
	private function read_request_body(){
		$this->__app_body=file_get_contents("php://input");
		return $this;
	}


	/*use to assign the data to global variables to be used in X-PAP-AUTHENTICATION Header*/
	function authenticate(){
		$this->__app_body=json_decode($this->__app_body);
		$this->__app_id=isset($this->__app_body->app_id)?$this->__app_body->app_id:NULL;
		$this->__app_mode=isset($this->__app_body->mode)?$this->__app_body->mode:NULL;
		$this->__app_token=isset($this->__app_body->token)?$this->__app_body->token:NULL;

		self::$TOKEN=$this->__app_token;
		self::$ID=$this->__app_id;

		#public credentials 
		$this->__app_credentials=['app_id'=>$this->__app_id,'token'=>$this->__app_token,'expiration'=>$this->__app_expiration];

		#if mode is present
		if(!is_null($this->__app_mode)){
			$this->__app_credentials['mode']=$this->__app_mode;
		}

		#using Grant option | Username and Password are required
		if(trim(strtolower($this->__app_header))=='grant'){ 
			self::grant(); 
		}	

		#assign to static variable
		self::$CREDENTIALS=$this->__app_credentials;
		return $this;
	}


	/*used for assiging data for X-PAP-CONTENT Header*/ 
	function content(){
		$this->__app_body=json_decode($this->__app_body);
		$this->__app_session=isset($this->__app_body->session_id)?$this->__app_body->session_id:NULL;
		$this->__app_key=isset($this->__app_body->key)?$this->__app_body->key:NULL;
		$this->__app_credentials['session_id']=$this->__app_session;
		$this->__app_credentials['key']=$this->__app_key;
		self::$CREDENTIALS=$this->__app_credentials;
		return $this;
	}


	/*Grant option*/
	function grant(){
		self::$GRANT=true;  
		$this->__app_username=isset($this->__app_body->username)?$this->__app_body->username:NULL; 
		$this->__app_password=isset($this->__app_body->password)?$this->__app_body->password:NULL; 

		#assign to credentials
		$this->__app_credentials['username']=$this->__app_username;
		$this->__app_credentials['password']=$this->__app_password;



		#drop mode to prevent R/W mode in grant <default 444>
		unset($this->__app_credentials['mode']);
		return $this;	
	}


	/*set expiration in second(s)*/
	function expires($seconds){
		$this->__app_expiration=$seconds;
		$this->__app_credentials['expiration']=$this->__app_expiration;
		self::$CREDENTIALS=$this->__app_credentials;
		return $this;
	}


	/*generating token and key*/
	function key($salt,callable $algorithm){
		#generate token and pre-computed Key
		$this->__app_salt=$salt;
		$this->__app_token=$this->__app_token.microtime(true);
		$this->__app_token=sha1($this->__app_token.$this->__app_salt);
		$this->__app_key=sha1($this->__app_token.$this->__app_salt);

		#assign to credential
		$this->__app_credentials['token']=$this->__app_token;
		$this->__app_credentials['key']=$this->__app_key;
		self::$CREDENTIALS=$this->__app_credentials;

		#calback function overrides the default token and key
		call_user_func_array($algorithm,array($this));
		return $this;
	}


	/*overide default key | This must be used inside the self::key function*/
	function overide($key){
		$this->__app_credentials['key']=$key;
		self::$CREDENTIALS=$this->__app_credential;
		return $this;
	}

	

}

?>