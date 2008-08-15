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

require_once 'GaduAPICore.php';     

/**
* @desc Klient GaduAPI, wymaga biblioteki  http://oauth.googlecode.com/svn/code/php/OAuth.php
* 
* @package		GaduAPI
* @author       Gadu-Gadu S.A.
* @copyright    Copyright © 2008, Gadu-Gadu S.A.
* @license      Licenced for use under the LGPL. See http://www.gnu.org/licenses/lgpl-3.0.txt
*/
class GaduAPI extends GaduAPICore
{
    /**
    * @desc Pobranie danych użytkownika o podanym numerze UIN
    * 
    * @param string     $uin    numer użytkownika
    * @return mixed     dane o użytkowniku
    */
    public function getUser($uin){
        return $this->doRequest('GET', '/users/'.(int)$uin);
    }
    /**
    * @desc Zapisanie danych użytkownika o podanym numerze UIN
    * 
    * @param string     $uin    numer użytkownika
    * @param mixed      $params parametry do zapisania
    * @return mixed     dane o użytkowniku
    */
    public function saveUser($uin, $params){
        return $this->doRequest('POST', '/users/'.(int)$uin, array_merge((array) $params, array('_method' => 'PUT')));
    }
    /**
    * @desc Szukanie użytkowników w katalogu publicznym
    * 
    * @param array      $searchParams   kryteria wyszukiwania
    * @return mixed     dane o użytkowniku
    */    
    public function getUsers($searchParams){
        return $this->doRequest('GET', '/users', (array) $searchParams);
    }
    /**
    * @desc Pobranie listy URI do awatarów użytkownika o podanym numerze UIN
    * 
    * @param string     $uin            numer użytkownika 
    * @param int        $avatarNumber   numer awatara użytkowniaka
    * @return mixed     czy operacja się powiodła
    */    
    public function getUserAvatar($uin, $avatarNumber = null){
    
        return $this->doRequest('GET', '/avatars/'.(int)$uin.($avatarNumber != null ? '/'.(int) $avatarNumber : ''));
    }
    /**
    * @desc Zapisanie awatara użytkownika o podanym numerze UIN
    * 
    * @param string     $uin            numer użytkownika 
    * @param int        $avatarNumber   numer awatara użytkowniaka
    * @param mixed      $file           nazwa lokalnego pliku z awatarem
    * @return mixed     czy operacja się powiodła
    */    
    public function saveUserAvatar($uin, $avatarNumber, $file){
 
        return $this->doRequest('POST', '/avatars/'.(int)$uin.'/'.(int) $avatarNumber, array('avatar' => '@'.realpath($file),'_method' => 'PUT'));
    }
    
}
?>