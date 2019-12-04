<?php

/**
 * lib/CiscoParse.php.
 *
 *
 *
 * PHP version 5
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * @category  default
 *
 * @author    Andrew Jones
 * @copyright 2016 @authors
 * @license   http://www.gnu.org/copyleft/lesser.html The GNU LESSER GENERAL PUBLIC LICENSE, Version 3.0
 */

namespace ohtarr;

class CiscoParse
{
	//public $NM_DEVICES = json_decode();

	public $os = "";
	public $input = [
		"run" 			=>	"",
		"version" 		=>	"",
		"inventory"		=>	"",
		"cdp"			=>	"",
		"lldp"			=>	"",
		"interfaces"	=>	"",
		"stp"			=>	"",
		"switchport"	=>	"",
	];
	//public $interfaces = [];
	public $output = [];

/* 	public function __construct($array)
	{
		foreach($array as $key => $value)
		{
			if(array_key_exists($key,$this->input))
			{
				$this->input[$key] = $value;
			}
		}
		$parser = $this->update();
		return $parser;
	} */

	public static function create($array)
	{
		$os = self::parse_version_to_os2($array['version']);
		if($os == "ios")
		{
			require_once("cisco_ios_parse.php");
			$parser = new \ohtarr\CiscoIosParse($array);
			return $parser;
		}

		if($os == "iosxe")
		{
			require_once("cisco_iosxe_parse.php");
			$parser = new \ohtarr\CiscoIosxeParse($array);
			return $parser;
		}
		
		if($os == "nxos")
		{
			require_once("cisco_nxos_parse.php");
			$parser = new \ohtarr\CisconxosParse($array);
			return $parser;
		}
	
		if($os == "iosxr")
		{
			//require_once("cisco_iosxr_parse.php");
		}
	}

/* 	public function input_data($data,$cmdtype)
	{
		if(array_key_exists($cmdtype,$this->input))
		{
			$this->input[$cmdtype] = $data;
			$this->update();
		}
	} */

/* 	public function update()
	{
		if($this->input['version'])
		{
			$this->os = $this->parse_version_to_os();
			if(!$this->os)
			{
				//exit("Unable to determine OS type!");
			}
		} else {
			//exit("Unable to determine OS type!");
		}

		if($this->os == "ios")
		{
			require_once("cisco_ios_parse.php");
			$parser = new \ohtarr\CiscoIosParse($this->input);
			return $parser;
		}

		if($this->os == "iosxe")
		{
			require_once("cisco_iosxe_parse.php");
			$parser = new \ohtarr\CiscoIosxeParse($this->input);
			return $parser;
		}
		
		if($this->os == "nxos")
		{
			require_once("cisco_nxos_parse.php");
			$parser = new \ohtarr\CisconxosParse($this->input);
			return $parser;
		}
	
		if($this->os == "iosxr")
		{
			//require_once("cisco_iosxr_parse.php");
		}
		
		/* if($this->os)
		{
			$parser->input_data($this->input['run'],"run");
			$parser->input_data($this->input['version'],"version");
			$parser->input_data($this->input['inventory'],"inventory");
			$parser->input_data($this->input['cdp'],"cdp");
			$parser->input_data($this->input['lldp'],"lldp");
			$parser->input_data($this->input['interfaces'],"interfaces");
			$parser->input_data($this->input['stp'],"stp");
			$parser->input_data($this->input['switchport'],"switchport");
			//$parser->update();
			$this->output = $parser->output;
		} 
	} /**/
	
/* 	public function parse_version_to_os()
	{
		$reg1 = "/Cisco (IOS) Software/m";
		if (preg_match($reg1, $this->input['version'], $HITS1))
		{
			$os = "ios";
		}

		$reg2 = "/Cisco (IOS XE) Software/m";
		if (preg_match($reg2, $this->input['version'], $HITS2))
		{
			$os = "iosxe";
		}

		$reg3 = "/Cisco Nexus Operating System \(NX-OS\) Software/";
		if (preg_match($reg3, $this->input['version'], $HITS3))
		{
			$os = "nxos";
		}
		
		$reg4 = "/Cisco IOS XR Software/";
		if (preg_match($reg4, $this->input['version'], $HITS4))
		{
			$os = "iosxr";
		}
		
		return $os;
	} */

	public static function parse_version_to_os2($version)
	{
		$reg1 = "/Cisco (IOS) Software/m";
		if (preg_match($reg1, $version, $HITS1))
		{
			$os = "ios";
		}

		$reg2 = "/Cisco (IOS XE) Software/m";
		if (preg_match($reg2, $version, $HITS2))
		{
			$os = "iosxe";
		}

		$reg3 = "/Cisco Nexus Operating System \(NX-OS\) Software/";
		if (preg_match($reg3, $version, $HITS3))
		{
			$os = "nxos";
		}
		
		$reg4 = "/Cisco IOS XR Software/";
		if (preg_match($reg4, $version, $HITS4))
		{
			$os = "iosxr";
		}
		
		return $os;
	}
}