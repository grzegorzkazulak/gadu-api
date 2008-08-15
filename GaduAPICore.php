<?php
/* * * * * * * * * * * *

Licenced for use under the LGPL. See http://www.gnu.org/licenses/lgpl-3.0.txt.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
 
This licence is there: http://www.gnu.org/licenses/lgpl-3.0.txt.
 
This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS /FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.
 
* * * * * * * * * * * * */

require_once 'OAuth.php';
/**
* @desc Podstawowa klasa GaduAPI realizuje niskopoziomowe zapytania do API, wymaga biblioteki  http://oauth.googlecode.com/svn/code/php/OAuth.php
*
* @package      GaduAPI
* @author       Gadu-Gadu S.A.
* @copyright    Copyright © 2008, Gadu-Gadu S.A.
* @license      Licenced for use under the LGPL. See http://www.gnu.org/licenses/lgpl-3.0.txt
*/



abstract class GaduAPICore {
    
    /**
     * @desc    Informacje z curl_exec
     * @var     string
    */
    private $info;
    
    /**
     * @desc    Numer Gadu-Gadu zalogowanego użytkownika
     * @var     integer
    */
    private $uin = null;
    
    /**
     * @desc    Tablica ostatnich błędów
     * @var     array
    */
    private $lastError;

    /**
     * @desc    Typ formatu odpowiedzi z serwera.   
     * @var         integer
    */
    protected $responseType = 'phps';
    
    /**
     * @desc    Ostatnia odpowiedź serwera
     * @var     string
    */
    protected $response;
    
    /**
     * @desc    Obiekt consumera OAuth
     * @var     object
    */
    protected $consumer = null;
    
    /**
     * @desc    Obiekt autentykacji
     * @var     object
    */
    protected $oauthSigMethod = null;
    
    /**
     * @desc    Token Oauth
     * @var     string
    */
    protected $oauthToken = null;
    
    /**
     * @desc    Url do api
     * @var     string
    */
    protected $apiRequestUrl = GADUAPI_REQUEST_URL;
    
    /**
     * @desc    Url do autoryzacji użytkownika
     * @var     string
    */
    protected $apiAuthorizationUrl = GADUAPI_AUTHORIZATION_URL;
    
    /**
     * @desc   Czas odpowiedzi
     * @var    integer
    */
    protected $requestTimeout = 3;
    
    /**
     * @desc    Ilość powtórzeń
     * @var     integer
    */
    protected $requestRetryCount = 3;
    
    /**
     * @desc    Wersja api 
     * @constant string
    */
    const VERSION = '0.1438';
    
    /**
     * @desc Konstruktor klasy
     * 
     * @param string  $consumer_key             Numer GG użytkownika do zalogowania
     * @param string  $consumer_secret          Hasło użytkownika do zalogowania
     * @access public 
     * @return void
    */
    public function __construct($consumer_key = null, $consumer_secret = null){

        $this->oauthConsumer  = new OAuthConsumer($consumer_key, $consumer_secret);
        $this->oauthSigMethod = new OAuthSignatureMethod_HMAC_SHA1(); 
    }
    /**
     * @desc Ustawienie access tokena
     *
     * @param OAuhtToken
     * @access public
     * @return bool
    */
    public function setAccessToken($accessToken){
        if(empty($accessToken->key) || empty($accessToken->secret))
            return false; 
        $this->oauthToken = $accessToken;
        return true; 
    }
    /**
     * @desc Przeprowadzenie autoryzacji request token po stronie Gadu-Gadu
     * 
     * @param  string  $callbackURL                 url na który ma przekierować Gadu-Gadu po poprawnej autoryzacji
     * @param  string  $callbackURLFail             url na który ma przekierowa. Gadu-Gadu po niepoprawnej autoryzacji
     * @access public
     * @return void
    */
    public function loginUser($callbackURL){
        session_start();
        if(empty($_SESSION['access_token'])){
            $this->setAccessToken($_SESSION['access_token']);
            $this->uin = $_SESSION['uin']; 
        }elseif(empty($_SESSION['request_token'])){
            $_SESSION['access_token'] = $this->getAccessToken($_SESSION['request_token']);
            $_SESSION['uin']          = $this->uin;   
        }
        else{
            $_SESSION['request_token'] = $this->getRequestToken();
            header('Location: '.$this->apiAuthorizationUrl.'?'.http_build_query(array('callback_url' => $callbackURL, 'request_token' => $_SESSION['request_token']->key)));
            die();
        }
    }

    /**
     * @desc Pobranie request_token
     * 
     * @access public
     * @return OAuthToken 
    */
    public function getRequestToken(){
        for($c=0; $c < $this->requestRetryCount ;$c++){
             $req_req    = OAuthRequest::from_consumer_and_token($this->oauthConsumer, NULL, 'POST', $this->getRequestURL('POST', '/request_token'), array());
             $req_req->sign_request($this->oauthSigMethod, $this->oauthConsumer, NULL);
             $apiRequest = $this->ggApiRequest('POST', '/request_token', array(), 'Authorization: OAuth '.$req_req->to_header());
             if($apiRequest !== false)
                return new OAuthToken($apiRequest['result']['oauth_token'], $apiRequest['result']['oauth_token_secret']);
        }
        throw new GaduAPIException($this->getLastError(), 408);
    }

    /**
     * @desc Pobranie access_token
     * 
     * @param  OAuthToken  $requestToken obiekt request token do wymiany na acccess token
     * @access public
     * @return bool        czy autoryzacja request token się powiodła 
    */
    public function getAccessToken($requestToken = null){
        if(!is_null($requestToken)){
            if(is_null($requestToken->key))
               throw new GaduAPIException('Empty request token');
            for($c=0; $c < $this->requestRetryCount ; $c++){
                $acc_req    = OAuthRequest::from_consumer_and_token($this->oauthConsumer, $requestToken, 'POST', $this->getRequestURL('POST', '/access_token'), array());
                $acc_req->sign_request($this->oauthSigMethod, $this->oauthConsumer, $requestToken);  
                $apiRequest = $this->ggApiRequest('POST', '/access_token', array(), 'Authorization: OAuth '.$acc_req->to_header());
                if($apiRequest !== false){
                    $this->oauthToken = new OAuthToken($apiRequest['result']['oauth_token'], $apiRequest['result']['oauth_token_secret']);
                    $this->uin        = $apiRequest['result']['uin'];

                    return $this->oauthToken;  
                }
                usleep(100000);
            }
            throw new GaduAPIException($this->getLastError(), 408);
        }
        return $this->oauthToken;  
    }

    /**
     * @desc Zapytanie http do api realizowane przez użytkownika podpisane przez OAuth
     * 
     * @param string     $method     nazwa metody http: 'GET','POST','PUT','DELETE'
     * @param string     $uri        nazwa zasobu jako uri
     * @param mixed      $params     dodatkowe parametry zapytania
     * @param bool       $ssl            czy zapytanie jest po https
     * @param string     $responseType   w jakim formacie ma być odpowiedź z serwera
     * @access public
     * @return array     tablica elementów zwróconych przez API
    */
    public function doRequest($method, $uri, $params = null, $headers = null, $ssl = false, $responseType = 'phps'){
        for($c=0; $c < $this->requestRetryCount; $c++){
            $acc_headers = array();
            if(!empty($this->oauthConsumer->key) && (!empty($method) && $uri)){
                $acc_req     = OAuthRequest::from_consumer_and_token($this->oauthConsumer, 
                                                   $this->oauthToken, 
                                                   isset($params['_method']) ? $params['_method'] : $method, 
                                                   $this->getRequestURL($method, $uri, $params, $ssl, $responseType), 
                                                   array());
                $acc_req->sign_request($this->oauthSigMethod, $this->oauthConsumer, $this->oauthToken); 
                $acc_headers[] = 'Authorization: OAuth '.$acc_req->to_header(); 
            }
            $resp = $this->ggApiRequest($method, $uri, $params, array_merge((array) $headers, (array) $acc_headers), $ssl, $responseType);
            if($resp !== false)
               return $resp;
        }
        throw new GaduAPIException($this->getLastError(), 408);
    }
    /**
     * Pobranie numeru Gadu-Gadu zalogowanego użytkownika
     *
     * @access public
     * @return integer
    */
    public function getUIN(){
        return $this->uin;
    }

    /**
     * @desc Informacja zwracana przez biblioteke curl
     *       kody protokołu http http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
     *
     * @access public
     * @return string
    */
    public function getLastInfo(){
        return $this->info;
    }

    /**
     * @desc Pobierz kod odpowiedzi
     *
     * @access public
     * @return integer
    */
    public function getResponseCode(){
        return $this->info[0];
    }

    /**
     * @desc Translacja odpowiedzi do tablicy php w zależności od jej formatu
     * 
     * @param string     $response   odpowiedź serwera
     * @access public
     * @return mixed
    */
    public function parseResponse($response, $type){
        switch($type){
            case 'xml':
                $parsedResponse = $this->parseXML($response);
                break;
            case 'json':
                $parsedResponse = $this->parseJSON($response);
                break;               
            default:
                if(!$parsedResponse = @unserialize($response)){
                    $this->lastError =  'Bad response : '.$response;
                    throw new GaduAPIParseException($this->getLastError(), 400);
          		}
        }                                    
        return  $parsedResponse;
    }

    /**
     * Pobranie odpowiedzi z serwera
     *
     * @access public
     * @return string
    */
    public function getRawResponse(){
        return $this->response;
    }
    /**
     * @desc Zapytanie http do api
     * 
     * @param string     $method         nazwa metody http: 'GET','POST','PUT','DELETE'
     * @param string     $uri            nazwa zasobu jako uri
     * @param mixed      $params         dodatkowe parametry zapytania
     * @param bool       $ssl            czy zapytanie jest po https
     * @param string     $responseType   w jakim formacie ma być odpowiedź z serwera
     * @access public
     * @return mixed     tablica elementów zwróconych przez API
    */
    protected function ggApiRequest($method, $uri, $params = null, $headers = null, $ssl = false, $responseType = 'phps'){

        if(!in_array($method, array('GET','POST','PUT','DELETE')))
            throw new GaduAPIException('Nieprawidłowa metoda');
        
        $ch = curl_init();
        if(($method == 'POST' || $method == 'PUT')){
            $simpleParams = http_build_query((array)$params, null, '&'); 
            curl_setopt($ch,CURLOPT_POSTFIELDS, !preg_match('/=%40/', $simpleParams) ? $simpleParams : $params);
        } 
        if($method != 'POST') {
            curl_setopt($ch,CURLOPT_CUSTOMREQUEST, $method);
        }

        curl_setopt($ch,CURLOPT_URL, $this->getRequestURL($method, $uri, $params, $ssl, $responseType));  
        curl_setopt($ch,CURLOPT_HTTPHEADER, array_merge((array) $headers,array('Expect: ',
                                                              'User-Agent: GGAPI PHP v '.self::VERSION,
                                                              ) ));                                                        
        curl_setopt($ch,CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch,CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch,CURLOPT_MAXREDIRS, 3);
        curl_setopt($ch,CURLOPT_TIMEOUT, $this->requestTimeout); 
        
        $this->response  = curl_exec($ch);
        $this->lastError = curl_error($ch);
        $this->info      = curl_getinfo($ch);
        curl_close($ch);
        if($this->response === false)
           return false;

        if($this->info['http_code'] !== 200){
            try{
                $parsedResponse = $this->parseResponse($this->response, $responseType);
            } catch(GaduAPIParseException $e) {
                $parsedResponse = array('result' => array('errorMsg' => $this->info['http_code']));
            }
            switch($this->info['http_code']){
                case 401:
                   throw new GaduAPIUnauthorizedException($parsedResponse['result']['errorMsg'], $this->info['http_code']);
                case 403:
                   throw new GaduAPIForbiddenException($parsedResponse['result']['errorMsg'], $this->info['http_code']);
                default:
                    throw new GaduAPIException($parsedResponse['result']['errorMsg'], $this->info['http_code']);
            }
        }else{
           $parsedResponse = $this->parseResponse($this->response, $responseType);
        }
        return $parsedResponse;
    }

    /**
     * @desc Pobranie adresu url zapytania do api
     * 
     * @param string     $method     nazwa metody http: 'GET','POST','PUT','DELETE'
     * @param string     $uri        nazwa zasobu jako uri
     * @param mixed      $params     dodatkowe parametry zapytania
     * @param bool       $ssl        czy zapytanie jest po https
     * @access protected 
     * @return string 
    */
    protected function getRequestURL($method, $uri, $params = null, $ssl = false, $responseType = 'phps'){
        return ($ssl ? 'https' : 'http').strstr($this->apiRequestUrl, '://').$uri.($responseType ? '.'.$responseType : '').(is_array($params) && count($params) > 0 && $method == 'GET' ? '?'.http_build_query($params) : '');
    }

    /**
     * @desc Pobierz ostatni błąd z zapytania
     *
     * @access public
     * @return string
    */
    public function getLastError(){
        return $this->lastError;
    }

    /**
     * @desc Translacja XML do PHP
     *
     * @param string     $input      zawartosc dokumentu XML do zamiany ta tablice PHP
     * @access public
     * @return void
    */
    protected function parseXML($input){
		if (empty($input))
			throw new GaduAPIException('Response is empty', 408);
	
        $sxml = simplexml_load_string($input); 
     
        $arr = array();
        if ($sxml) {
          foreach ($sxml as $k => $v) {
            if ($sxml['list']) {
              $arr[] = self::convert_simplexml_to_array($v);
            } else {
              $arr[$k] = self::convert_simplexml_to_array($v);
            }
          }
        }
        if (count($arr) > 0) {
          return $arr;
        } else {
          return (string)$sxml;
        }
    }
    /**
     * @desc Translacja JSON do PHP
     * 
     * @param string     $input      tablica JSON do zamiany na tablicę PHP     
     * @return string
    */
    protected function parseJSON($input){
		if (empty($input)){
			throw new GaduAPIException('Response is empty, Cannot translate', 408);
		}
			
        return json_decode($input, true);
    }

    /**
     * Konwertuje obiekt typu SimpleXML do tablicy PHP
     *
     * @param string    $sxml		
     * @return void
    */
    public static function convert_simplexml_to_array($sxml) {
		
        $arr = array();
        if ($sxml) {
          foreach ($sxml as $k => $v) {
                if($arr[$k]){
                    $arr[$k." ".(count($arr) + 1)] = self::convert_simplexml_to_array($v);
                }else{
                    $arr[$k] = self::convert_simplexml_to_array($v);
                }
            }
        }
        if (count($arr) > 0) {
          return $arr;
        } else {
          return (string)$sxml;
        }
    } 
}

class GaduAPIException extends Exception{
}
class GaduAPIParseException extends GaduAPIException{
}
class GaduAPIUnauthorizedException extends GaduAPIException {  
}
class GaduAPIForbiddenException extends GaduAPIException {  
}