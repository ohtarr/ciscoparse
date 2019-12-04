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

class CiscoIosParse
{
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
	public $output = [
		'system' 		=>	[],
		'ips'			=>	[],
		'interfaces'	=>	[],
	];

	public function __construct($array)
	{
		if(is_array($array))
		{
			foreach($array as $key => $value)
			{
				if(array_key_exists($key,$this->input))
				{
					$this->input[$key] = $value;
				}
				$this->update();
			}
		}
	}

	public function __destruct()
	{

	}

	public function input_data($data,$cmdtype)
	{
		if(array_key_exists($cmdtype,$this->input))
		{
			$this->input[$cmdtype] = $data;
			$this->update();
		}
	}

	public function update()
	{
		$this->output = [
			'system' 		=>	[],
			'ips'			=>	[],
			'interfaces'	=>	[],
		];
		if($this->input['run'])
		{
			$this->output['system']['hostname'] = $this->parse_run_to_hostname($this->input['run']);
			$this->output['system']['usernames'] = $this->parse_run_to_usernames($this->input['run']);
			$this->output['system']['domain'] = $this->parse_run_to_domain($this->input['run']);
			$this->output['system']['nameservers'] = $this->parse_run_to_name_servers($this->input['run']);
			$this->output['ips'] = $this->parse_run_to_ips($this->input['run']);
			$this->output['interfaces'] = $this->parse_run_to_interfaces($this->input['run']);
			//$this->output['interfaces'] = array_merge_recursive($this->output['interfaces'],$this->parse_run_to_interfaces($this->input['run']));
			$this->output['system']['mgmt'] = $this->parse_run_to_mgmt_interface($this->input['run']);
			$this->output['system']['vrfs'] = $this->parse_run_to_vrfs($this->input['run']);
			$this->output['system']['ntp'] = $this->parse_run_to_ntp($this->input['run']);
			$this->output['dnsnames'] = $this->generate_dns_names();
			$this->output['system']['snmp']['location'] = $this->parse_run_to_snmp_location($this->input['run']);
		}

		if($this->input['version'])
		{
			$this->output['system']['hostname'] = $this->parse_version_to_hostname($this->input['version']);
			$this->output['system']['uptime'] = $this->parse_version_to_uptime($this->input['version']);
			$this->output['system']['model'] = $this->parse_version_to_model($this->input['version']);
			$this->output['system']['os'] = $this->parse_version_to_ios($this->input['version']);
			$this->output['system']['ram'] = $this->parse_version_to_ram($this->input['version']);
			$this->output['system']['serial'] = $this->parse_version_to_serial($this->input['version']);
			$this->output['system']['license'] = $this->parse_version_to_license($this->input['version']);
			$this->output['system']['confreg'] = $this->parse_version_to_confreg($this->input['version']);
		}

		if($this->input['inventory'])
		{
			$this->output['system']['inventory'] = $this->parse_inventory($this->input['inventory']);
			$this->output['system']['serial'] = $this->parse_inventory_to_serial($this->input['inventory']);
		}

		if($this->input['lldp'])
		{
			$this->output['neighbors']['lldp'] = $this->parse_lldp_to_neighbors($this->input['lldp']);
			
		}

		if($this->input['cdp'])
		{
			$this->output['neighbors']['cdp'] = $this->parse_cdp_to_neighbors($this->input['cdp']);
		
		}

		if($this->input['interfaces'])
		{
			
		}

		if($this->input['switchport'])
		{
			//$this->output['interfaces'] = array_replace_recursive($this->output['interfaces'],$this->parse_switchport_to_interfaces());
		}

		if($this->input['stp'])
		{
			
		}
		$this->merge_neighbors();
	}

	public static function netmask2cidr($netmask)
	{
		$bits = 0;
		$netmask = explode(".", $netmask);

		foreach($netmask as $octect)
			$bits += strlen(str_replace("0", "", decbin($octect)));
		return $bits;
	}

	public static function cidr2network($ip, $cidr)
	{
		$network = long2ip((ip2long($ip)) & ((-1 << (32 - (int)$cidr))));
		return $network;
	}

	public static function parse_run_to_usernames($run)
	{
		$reg1 = "/^username (\S+).*/m";
		$reg2 = "/privilege (\d+)/m";
		$reg3 = "/secret (\d+) (\S+)/m";

		//find all usernames lines
		if(preg_match_all($reg1, $run, $HITS))
		{
			//print_r($HITS);
			foreach($HITS[1] as $HKEY => $HIT)
			{
				//find privilege level of each
				if(preg_match_all($reg2, $HITS[0][$HKEY], $HITS2))
				{
					$usernames[$HITS[1][$HKEY]]['privilege'] = $HITS2[1][0];
				}
				if(preg_match_all($reg3, $HITS[0][$HKEY], $HITS3))
				{
					//print_r($HITS3);
					$usernames[$HITS[1][$HKEY]]['encryption'] = $HITS3[1][0];
					$usernames[$HITS[1][$HKEY]]['secret'] = $HITS3[2][0];					
				}
			}
		}
		//print_r($usernames);
		return $usernames;
	}

	public static function parse_run_to_hostname($run)
	{
		$reg1 = "/^hostname (\S+)/m";

		//find hostname line
		if(preg_match_all($reg1, $run, $HITS))
		{
			//print_r($HITS);
			return $HITS[1][0];
		}
	}

	public static function parse_run_to_domain($run)
	{
		$reg1 = "/^ip domain-name (\S+)/m";
		$reg2 = "/^ip domain name (\S+)/m";
		if(preg_match_all($reg1, $run, $HITS))
		{
			$domain = $HITS[1][0];
		}
		if(preg_match_all($reg2, $run, $HITS))
		{
			$domain = $HITS[1][0];
		}
		return $domain;
	}

	public static function parse_run_to_name_servers($run)
	{
		$reg1 = "/^ip name-server (\S+)/m";
		if(preg_match_all($reg1, $run, $HITS))
		{
			foreach($HITS[1] as $key => $server)
			{
				//print_r($HITS);
				$servers[] = $server;
			}
		}
		return $servers;
	}

	public static function parse_run_to_vrfs($run)
	{
		$vrfs = [];
		$reg = "/vrf definition (\S+)/";
		if(preg_match_all($reg, $run, $HITS, PREG_SET_ORDER))
		{
			foreach($HITS as $vrf)
			{
				$vrfs[] = $vrf[1];
			}
		}
		return $vrfs;
	}

	public static function parse_run_to_aaa($run)
	{
	
	}
	
	public function parse_run_to_snmp_location($run)
	{
		if(preg_match("/snmp-server location (.*)/", $run, $HITS1))
		{
			$return['string'] = $HITS1[1];
			$array = json_decode($HITS1[1],true);
			if(is_array($array))
			{
				foreach($array as $key => $value)
				{
					$return['json'][$key] = $value;
				}
			}
		}
		return $return;
	}
	
	public static function parse_run_to_ntp($run)
	{
		$reg = "/ntp server (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/";
		$reg2 = "/ntp server vrf (\S+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/";
		$reg3 = "/ntp source (\S+)/";
		if(preg_match_all($reg, $run, $HITS, PREG_SET_ORDER))
		{
			//print_r($HITS);
			foreach($HITS as $ntp1)
			{
				$ntp['servers'][] = $ntp1[1];
			}
		} 
		if (preg_match_all($reg2, $run, $HITS2, PREG_SET_ORDER)) {
			//print_r($HITS2);
			foreach($HITS2 as $ntp2)
			{
				//$ntp[] = $ntp2[2];
				$ntp['servers'][$ntp2[2]]['vrf'] = $ntp2[1];
			}
		}
		if (preg_match($reg3, $run, $HITS3)) {
			//print_r($HITS3);
			$ntp['sourceint'] = $HITS3[1];
		}
		
		//print_r($ntp);
		return $ntp;
	}
	
	public static function parse_run_to_policymap($run)
	{

	}

	public static function parse_version_to_uptime($version)
	{
		$reg1 = "/uptime is (.+)/m";
		$reg2 = "/(\d+) year/m";
		$reg3 = "/(\d+) week/m";
		$reg4 = "/(\d+) day/m";
		$reg5 = "/(\d+) hour/m";
		$reg6 = "/(\d+) minute/m";

		if(preg_match_all($reg1, $version, $HITS))
		{
			if(preg_match_all($reg2, $HITS[1][0], $HITS2))
			{
				$uptime['years'] = $HITS2[1][0];
			}
			if(preg_match_all($reg3, $HITS[1][0], $HITS3))
			{
				$uptime['weeks'] = $HITS3[1][0];
			}
			if(preg_match_all($reg4, $HITS[1][0], $HITS4))
			{
				$uptime['days'] = $HITS4[1][0];
			}
			if(preg_match_all($reg5, $HITS[1][0], $HITS5))
			{
				$uptime['hours'] = $HITS5[1][0];
			}
			if(preg_match_all($reg6, $HITS[1][0], $HITS6))
			{
				$uptime['minutes'] = $HITS6[1][0];
			}
		}

		return $uptime;
	}

	public static function parse_version_to_model($version)
	{
			if (preg_match('/.*isco\s+(WS-\S+)\s.*/', $version, $reg))
			{
			$model = $reg[1];

			return $model;
		}
		if (preg_match('/.*isco\s+(OS-\S+)\s.*/', $version, $reg))
		{
			$model = $reg[1];

			return $model;
		}
		if (preg_match('/.*ardware:\s+(\S+),.*/', $version, $reg))
		{
			$model = $reg[1];

			return $model;
		}
		if (preg_match('/.*ardware:\s+(\S+).*/', $version, $reg))
		{
			$model = $reg[1];

			return $model;
		}
		if (preg_match('/^[c,C]isco\s(\S+)\s\(.*/m', $version, $reg))
		{
			$model = $reg[1];

			return $model;
		}
	}
	
	
	public static function parse_version_to_ios($version)
	{
		$reg1 = "/Cisco (IOS) Software/m";
		$reg2 = "/Cisco (IOS XE) Software/m";
		if (preg_match($reg1, $version, $HITS1))
		{
			$os['type'] = $HITS1[1];
		}
		if (preg_match($reg2, $version, $HITS2))
		{
			$os['type'] = $HITS2[1];
		}
		$reg3 = '/System image file is "\S+:\/{0,1}(\S+)"/m';
		if (preg_match($reg3, $version, $HITS3))
		{
			$os['version'] = $HITS3[1];
		}
		$reg4 = '/Compiled \S+ (\S+)/';
		if (preg_match($reg4, $version, $HITS4))
		{
			$os['date'] = $HITS4[1];
		}		
		return $os;
	}
	
	public static function parse_version_to_license($version)
	{
		$reg1 = "/License Level: (\S+)/";
		if (preg_match($reg1, $version, $HITS1))
		{
			$license[$HITS1[1]]['current'] = $HITS1[1];
			$reg2 = "/License Type: (\S+)/";
			if (preg_match($reg2, $version, $HITS2))
			{
				$license[$HITS1[1]]['type'] = $HITS2[1];
			}
			$reg3 = "/Next reload license Level: (\S+)/";
			if (preg_match($reg3, $version, $HITS3))
			{
				$license[$HITS1[1]]['reboot'] = $HITS3[1];
			}
		}

		$reg = [
			"ipbase"	=>	"/ipbase\s+(ipbasek9|None)\s+(Permanent|None)\s+(ipbasek9|none)/",
			"security"	=>	"/security\s+(securityk9|None)\s+(Permanent|None)\s+(securityk9|None)/",
			"uc"		=>	"/uc\s+(uck9|None)\s+(Permanent|None)\s+(uck9|None)/",
			"data"		=>	"/data\s+(datak9|None)\s+(Permanent|None)\s+(datak9|None)/",
		];
		foreach($reg as $package => $reg)
		{
			if (preg_match($reg, $version, $HITS))
			{
				if($HITS[1] != "None")
				{
					$license[$package]['current'] = $HITS[1];
					$license[$package]['type'] = $HITS[2];
					$license[$package]['reboot'] = $HITS[3];
				}
			}
		}
		return $license;		
	}

	public static function parse_version_to_confreg($version)
	{
		$reg = "/Configuration register is (\S+)/";
		if (preg_match($reg, $version, $HITS1))
		{
			$confreg = $HITS1[1];
		}
		return $confreg;
	}
	
	public static function parse_version_to_ram($version)
	{
		$reg1 = "/with (\d+\S|\d+\S\/\d+\S) bytes of memory/m";
		if (preg_match($reg1, $version, $HITS1))
		{
			$ram = $HITS1[1];
		}
		return $ram;
	}

	public static function parse_version_to_hostname($version)
	{
		$reg1 = "/(\S+) uptime/";
		if (preg_match($reg1, $version, $HITS1))
		{
			$hostname = $HITS1[1];
		}
		return $hostname;
	}


	public static function parse_version_to_serial($version)
	{
		$reg1 = "/^Processor board ID (\S+)/m";
		if (preg_match($reg1, $version, $HITS1))
		{
			$serial = $HITS1[1];
		}
		return $serial;
	}
	
	public static function parse_run_to_ips($run)
	{
		$reg1 = "/ip address (\d+.\d+.\d+.\d+) (\d+.\d+.\d+.\d+)/";
		
		foreach(explode("\n", $run) as $line)
		{
			if (preg_match($reg1, $line, $HITS1))
			{
				$ips[$HITS1[1]]['network'] = self::cidr2network($HITS1[1],self::netmask2cidr($HITS1[2]));
				$ips[$HITS1[1]]['mask'] = $HITS1[2];
				$ips[$HITS1[1]]['cidr'] = self::netmask2cidr($HITS1[2]);
			}
		}
		return $ips;
	}

/*
	function parse_run_to_subnets()
	{
		$reg1 = "/ip address (\d+.\d+.\d+.\d+) (\d+.\d+.\d+.\d+)/";
		
		foreach(explode("\n", $this->input['run']) as $line)
		{
			if (preg_match($reg1, $line, $HITS1))
			{
				$cidr = $this->netmask2cidr($HITS1[2]);
				$subnet = $this->cidr2network($HITS1[1],$cidr);
				$subnets[$subnet]['mask'] = $HITS1[2];
				$subnets[$subnet]['cidr'] = $cidr;
			}
		}
		return $subnets;
	}
/**/

	public static function parse_interface_config($INTCFG)
	{
		if(preg_match("/interface (\S+)/", $INTCFG, $HITS1))
		{
			$INTNAME = $HITS1[1];
			$INTARRAY['name']= $HITS1[1];
		}
//		$INTLINES = explode("\n",$INTCFG);
//		foreach($INTLINES as $INTLINE)
//		{
			if(preg_match("/^\s*shutdown$/m", $INTCFG, $HITS1))
			{
				$INTARRAY['shutdown'] = 1;
			}
			if(preg_match("/description (.*)/", $INTCFG, $HITS1))
			{
				$INTARRAY['description']['string'] = $HITS1[1];
				$descarray = json_decode($HITS1[1],true);
				if(is_array($descarray))
				{
					foreach($descarray as $key => $value)
					{
						$INTARRAY['description']['json'][$key] = $value;
					}
				}
			}
			if(preg_match("/[Ee]thernet/",$INTNAME) || preg_match("/[Pp]ort-channel/",$INTNAME))
			{
				if(preg_match("/switchport mode (.*)/", $INTCFG, $HITS1))
				{
					//print "match!\n";
					$INTARRAY['switchport']['mode'] = $HITS1[1];
				}
				if(preg_match("/switchport trunk encapsulation (.*)/", $INTCFG, $HITS1))
				{
					//print "match!\n";
					$INTARRAY['switchport']['encapsulation'] = $HITS1[1];
				}
				if(preg_match("/switchport trunk native vlan (\d+)/", $INTCFG, $HITS1))
				{
					$INTARRAY['switchport']['native_vlan'] = $HITS1[1];
				}
				if(preg_match("/switchport access vlan (\d+)/", $INTCFG, $HITS1))
				{
					$INTARRAY['switchport']['access_vlan'] = $HITS1[1];
				}
				if(preg_match("/switchport voice vlan (\d+)/", $INTCFG, $HITS1))
				{
					$INTARRAY['switchport']['voice_vlan'] = $HITS1[1];
				}
				//print "$INTCFG";
				if(preg_match("/speed (\d+)/", $INTCFG, $HITS1))
				{
					$INTARRAY['speed'] = $HITS1[1];
				}
				if(preg_match("/^\s*duplex (\S+)$/m", $INTCFG, $HITS1))
				{
					print "DUPLEX: " . $HITS1[1];
					$INTARRAY['duplex'] = $HITS1[1];
				}
			}
			if(preg_match("/bandwidth (\d+)/", $INTCFG, $HITS1))
			{
				$INTARRAY['bandwidth'] = $HITS1[1];
			}
			if(preg_match("/vrf forwarding (\S+)/", $INTCFG, $HITS1))
			{
				$INTARRAY['vrf'] = $HITS1[1];
			}
			if(preg_match("/ip address (\d+.\d+.\d+.\d+) (\d+.\d+.\d+.\d+)( secondary|)/", $INTCFG, $HITS1))
			{
				$INTARRAY['ip'][$HITS1[1]]['mask'] = $HITS1[2];
				$INTARRAY['ip'][$HITS1[1]]['cidr'] = self::netmask2cidr($HITS1[2]);
				$INTARRAY['ip'][$HITS1[1]]['network'] = self::cidr2network($HITS1[1],self::netmask2cidr($HITS1[2]));
				if($HITS1[3])
				{
					$INTARRAY['ip'][$HITS1[1]]['secondary'] = 1;
				}
			}
			if(preg_match("/ip address (dhcp|negotiated)/", $INTCFG, $HITS1))
			{
				$INTARRAY['ip'][$HITS1[1]] = 1;
			}
			if(preg_match_all("/ip helper-address (\S+)/", $INTCFG, $HITS1))
			{
				foreach($HITS1[1] as $helper)
				{
					$INTARRAY['helper'][] = $helper;
				}
			}
			if(preg_match("/standby version (\d)/", $INTCFG, $HITS1))
			{
				$INTARRAY['hsrp']['version'] = $HITS1[1];
			}
			if(preg_match_all("/standby (\d+) ip (\S+)/", $INTCFG, $HITS1))
			{
				foreach($HITS1[1] as $key => $group)
				{
					$INTARRAY['hsrp']['group'][$group]['ip'] = $HITS1[2][$key];
				}
			}
			if(preg_match_all("/standby (\d+) priority (\d+)/", $INTCFG, $HITS1))
			{
				foreach($HITS1[1] as $key => $group)
				{
					$INTARRAY['hsrp']['group'][$group]['priority'] = $HITS1[2][$key];
				}
			}
			if(preg_match("/ip mtu (\S+)/", $INTCFG, $HITS1))
			{
				$INTARRAY['ipmtu'] = $HITS1[1];
			}
			if(preg_match("/ip tcp adjust-mss (\S+)/", $INTCFG, $HITS1))
			{
				$INTARRAY['adjustmss'] = $HITS1[1];
			}
			if(preg_match("/service-policy output (\S+)/", $INTCFG, $HITS1))
			{
				$INTARRAY['service-policy'] = $HITS1[1];
			}
	//	}
		return $INTARRAY;
	}

	public static function parse_run_to_raw_interfaces($run)
	{
		$LINES = explode("\n", $run); 
		$INT = null;
		$INTCFG = "";
		foreach($LINES as $LINE)
		{
			if ($LINE == "")
			{
				continue;
			}
			$DEPTH  = strlen($LINE) - strlen(ltrim($LINE));

			if($DEPTH == 0)
			{
				if($INT)
				{
					$tmparray[] = $INTCFG;
					//$INTARRAY[$INT] = self::parse_interface_config($INT,$INTCFG);
					$INTCFG = "";
				}
				if (preg_match("/^interface (\S+)/", $LINE, $HITS))
				{
					$INT = strtolower($HITS[1]);
					$INTCFG .= $LINE . "\n";
				} else {
					$INT = null;
				}
				continue;
			}
			if($DEPTH > 0)
			{
				if($INT)
				{
					$INTCFG .= $LINE . "\n";
				}
			}
		}
		//return $INTARRAY;
		return $tmparray;
	}
	
	public static function parse_run_to_interfaces($run)
	{
		$interfaces = self::parse_run_to_raw_interfaces($run);
		foreach($interfaces as $interface)
		{
			$tmp = self::parse_interface_config($interface);
			$intname = strtolower($tmp['name']);
			$array[$intname] = $tmp;
			$array[$intname]['raw']= $interface;
		}
		return $array;
	}

	public static function parse_run_to_mgmt_interface($run)
	{
		$regs = [
			'/.*source.* (\S+)/',
			'/ip tacacs source-interface (\S+)/',
			'/ip ftp source-interface (\S+)/',
			'/ip tftp source-interface (\S+)/',
			'/logging source-interface (\S+)/',
			'/ntp source (\S+)/',
			'/snmp-server source-interface informs (\S+)/',
			'/snmp-server trap-source (\S+)/',
			'/ip flow-export source (\S+)/',	
		];
		$SOURCES = [];
		foreach($regs as $reg){
			if (preg_match($reg, $run, $HITS))
			{
				if(!isset($SOURCES[$HITS[1]]))
				{
					$SOURCES[$HITS[1]] = 0;
				}
				$SOURCES[$HITS[1]]++;
			}
		}
		array_multisort($SOURCES,SORT_DESC);
		foreach($SOURCES as $SOURCE => $COUNT)
		{
			$return['interface'] = $SOURCE;
			break;
		}
		$interfaces = self::parse_run_to_interfaces($run);
		if(isset($interfaces[$SOURCE]))
		{
			foreach($interfaces[$SOURCE]['ip'] as $ip => $mask)
			{
				$return['ip'] = $ip;
				break;
			}
		}
		return $return;
	}

	public static function parse_inventory($inventory)
	{
		$reg = '/NAME:\s*(\S.*\S),\s*DESCR:\s*(.*)\nPID:\s*(\S.*\S)\s*,\s*VID:\s*(\S.*\S)\s*,\s*SN:\s*(\S.*\S)/';
		if (preg_match_all($reg, $inventory, $HITS, PREG_SET_ORDER))
		{
			foreach($HITS as $key => $entity)
			{
				$item = [
					"name"	=>	$HITS[$key][1],
					"descr"	=>	$HITS[$key][2],
					"pid"	=>	$HITS[$key][3],
					"vid"	=>	$HITS[$key][4],
					"sn"	=>	$HITS[$key][5],
				];
				$inv[] = $item;
			}
			return $inv;
		}
	}

	public static function parse_inventory_to_serial($inventory)
	{
		$reg = '/NAME:\s*(\S.*\S),\s*DESCR:\s*(.*)\nPID:\s*(\S.*\S)\s*,\s*VID:\s*(\S.*\S)\s*,\s*SN:\s*(\S.*\S)/';
		if (preg_match_all($reg, $inventory, $HITS, PREG_SET_ORDER))
		{
			foreach($HITS as $key => $entity)
			{
				$sn = $HITS[$key][5];
				break;
			}
			return $sn;
		}
	}

	public static function name_unabbreviate($name)
	{
		$shortcuts = [
			"fa" 	=>	"fastethernet",
			"gi" 	=>	"gigabitethernet",
			"te" 	=>	"tengigabitethernet",
			"lo" 	=>	"loopback",
			"mu" 	=>	"multilink",
			"ge"	=>	"gigabitethernet",
			"fe"	=>	"fastethernet",
		];

		$name = strtolower($name);
		//print $name . "\n";
		foreach($shortcuts as $abbrev => $full)
		{
			$namereg = "/(" . $abbrev . ")(\d\S+|\d)/";
			//print $namereg . "\n";
			if(preg_match($namereg, $name, $hits))
			{
				//print_r($hits);
				$newname = $full . $hits[2];
				//print $newname . "\n";
				return $newname;
			}
		}
		return $name;
	}
	
	public static function name_abbreviate($name)
	{
		$shortcuts = [
			"fa" 	=>	"fastethernet",
			"gi" 	=>	"gigabitethernet",
			"te" 	=>	"tengigabitethernet",
			"lo" 	=>	"loopback",
			"mu" 	=>	"multilink",
			"ge"	=>	"gigabitethernet",
			"fe"	=>	"fastethernet",
		];

		$name = strtolower($name);
		//print $name . "\n";
		foreach($shortcuts as $abbrev => $full)
		{
			$namereg = "/(" . $full . ")(\d\S+|\d)/";
			//print $namereg . "\n";
			if(preg_match($namereg, $name, $hits))
			{
				//print_r($hits);
				$newname = $abbrev . $hits[2];
				//print $newname . "\n";
				return $newname;
			}
		}
		return $name;
	}

	public static function dns_name_converter($name)
	{
		$newname = self::name_abbreviate($name);
		$newname = str_replace("/","-",$newname);
		$newname = str_replace(".","-",$newname);
		return $newname;	
	}
	
	public function generate_dns_names()
	{
		foreach($this->output['interfaces'] as $intname => $intcfg)
		{
			if(isset($intcfg['ip']))
			{
				foreach($intcfg['ip'] as $ip => $ipcfg)
				{
					unset($tmparray);
					if(!isset($ipcfg['secondary']))
					{
						$tmparray['name'] = strtolower(self::dns_name_converter($intname) . "." . $this->output['system']['hostname'] . "." . $this->output['system']['domain']);
						$tmparray['type'] = "a";
						$tmparray['value'] = $ip;
						$dnsnames[] = $tmparray;
						break;
					}
					//$tmparray = 
				}
			}
		}

		if($this->output['system']['hostname'])
		{
			$tmparray['name'] = strtolower($this->output['system']['hostname']) . "." . $this->output['system']['domain'];
			$tmparray['type'] = "cname";
			$tmparray['value'] = strtolower($this->dns_name_converter($this->output['system']['mgmt']['interface']) . "." . $this->output['system']['hostname'] . "." . $this->output['system']['domain']);
			$dnsnames[] = $tmparray;
		}
		return $dnsnames;
	}

	public static function parse_cdp_to_neighbors($cdp)
	{
		$cdpreg = "/Device ID:.*Management address\(es\):/sU";
		if(preg_match_all($cdpreg,$cdp,$hits,PREG_SET_ORDER))
		{
			foreach($hits as $hit)
			{
				$cdpdevice = $hit[0];

				$reg = "/Device\s+ID:\s*(\S+)/";
				if(preg_match($reg,$cdpdevice,$hits))
				{
					$namearray = explode(".",$hits[1]);
					$devicename = strtoupper($namearray[0]);
					$tmparray['name'] = $devicename;
				}
				$reg = "/Entry address\(es\):\s+IP\s+address:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/";
				if(preg_match($reg,$cdpdevice,$hits))
				{
					$tmparray['ip'] = $hits[1];
				}
				$reg = "/\s*Platform:\s+(.+),\s+Capabilities:/";
				if(preg_match($reg,$cdpdevice,$hits))
				{
					$tmparray['model'] = $hits[1];
				}
				$reg = "/Interface:\s*(\S+),\s*Port ID\s*\(outgoing port\):\s*(\S+)/";	
				if(preg_match($reg,$cdpdevice,$hits))
				{
					$tmparray['localint'] = self::name_unabbreviate($hits[1]);
					$tmparray['remoteint'] = self::name_unabbreviate($hits[2]);
				}
				$reg = "/Version\s*:\s*\n(.*)advertisement\s+version:/s";
				if(preg_match($reg,$cdpdevice,$hits))
				{
					//print_r($hits);
					$tmparray['version'] = $hits[1];
				}
				$reg = "/Native\s+VLAN:\s*(\d+)/";
				if(preg_match($reg,$cdpdevice,$hits))
				{
					$tmparray['nativevlan'] = $hits[1];
				}
				$reg = "/Duplex:\s*(\S+)/";
				if(preg_match($reg,$cdpdevice,$hits))
				{
					$tmparray['duplex'] = $hits[1];
				}
				$neighbors[] = $tmparray;
				unset($tmparray);
			}
		}
		return $neighbors;
	}
	
	public static function parse_lldp_to_neighbors($lldp)
	{
		$lldpreg = "/Chassis id:.*Management Addresses:\s+IP:\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s/sU";
		if(preg_match_all($lldpreg,$lldp,$hits,PREG_SET_ORDER))
		{
			foreach($hits as $hit)
			{
				$lldpdevice = $hit[0];
			
				$reg = "/System\s+Name:\s+(\S+)/";
				if(preg_match($reg,$lldpdevice,$hits))
				{
					$namearray = explode(".",$hits[1]);
					$devicename = strtoupper($namearray[0]);
					$tmparray['name'] = $devicename;
				}
				$reg = "/Chassis id:\s*(\S+)/";
				if(preg_match($reg,$lldpdevice,$hits))
				{
					$tmparray['chassisid'] = $hits[1];
				}
				$reg = "/Port\s+id:\s+(\S+)/";
				if(preg_match($reg,$lldpdevice,$hits))
				{
					//print_r($hits);
					$tmparray['portid'] = self::name_unabbreviate($hits[1]);
				}
				$reg = "/Port\s+Description:\s+(\S+)/";
				if(preg_match($reg,$lldpdevice,$hits))
				{
					$tmparray['portdesc'] = $hits[1];
				}
				$reg = "/\s+IP:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/";
				if(preg_match($reg,$lldpdevice,$hits))
				{
					$tmparray['ip'] = $hits[1];
				}
				$reg = "/System Description:\s+\n(.*)\s+Time remaining/s";
				if(preg_match($reg,$lldpdevice,$hits))
				{
					$tmparray['version'] = $hits[1];
				}
				$neighbors[] = $tmparray;
				unset($tmparray);
			}
		}
		if(isset($neighbors))
		{
			return $neighbors;
		}
	}
	
	public function merge_neighbors()
	{
		if(isset($this->output['neighbors']['lldp']))
		{
			foreach($this->output['neighbors']['lldp'] as $lldpneighbor)
			{
				$this->output['neighbors']['all'][$lldpneighbor['name']]['chassisid'] = $lldpneighbor['chassisid'];
				$this->output['neighbors']['all'][$lldpneighbor['name']]['remoteint'] = $lldpneighbor['portid'];
				$this->output['neighbors']['all'][$lldpneighbor['name']]['portdesc'] = $lldpneighbor['portdesc'];
				$this->output['neighbors']['all'][$lldpneighbor['name']]['ip'] = $lldpneighbor['ip'];
				$this->output['neighbors']['all'][$lldpneighbor['name']]['version'] = $lldpneighbor['version'];
			}
		}
		if(isset($this->output['neighbors']['cdp']))
		{
			foreach($this->output['neighbors']['cdp'] as $cdpneighbor)
			{
				$this->output['neighbors']['all'][$cdpneighbor['name']]['model'] = $cdpneighbor['model'];
				$this->output['neighbors']['all'][$cdpneighbor['name']]['localint'] = $cdpneighbor['localint'];
				$this->output['neighbors']['all'][$cdpneighbor['name']]['remoteint'] = $cdpneighbor['remoteint'];
				$this->output['neighbors']['all'][$cdpneighbor['name']]['ip'] = $cdpneighbor['ip'];
				$this->output['neighbors']['all'][$cdpneighbor['name']]['version'] = $cdpneighbor['version'];
				if(isset($cdpneighbor['nativevlan']))
				{
					$this->output['neighbors']['all'][$cdpneighbor['name']]['nativevlan'] = $cdpneighbor['nativevlan'];
				}
				$this->output['neighbors']['all'][$cdpneighbor['name']]['duplex'] = $cdpneighbor['duplex'];
			}
		}
	}
	
	function parse_switchport_to_interfaces()
	{
		$array=[];
		$LINES = explode("\n", $this->input['switchport']); 
		$INT = null;
		$NEWINT = null;
		foreach($LINES as $LINE)
		{
			if ($LINE == "")
			{
				continue;
			}
			if(preg_match("/^Name: (\S+)/", $LINE, $HITS1))
			{
				$NEWINT = $HITS1[1];
				if(!$INT)
				{
					$INT = $NEWINT;
				}
				continue;
			}
			if($INT != $NEWINT)
			{
				$array[$this->name_unabbreviate($INT)] = $TMPARRAY;
				$TMPARRAY = null;
				$INT = $NEWINT;
			} elseif($INT) {
				$TMPARRAY[] = $LINE;
			}
		}
		if(isset($TMPARRAY))
		{
			$array[$this->name_unabbreviate($INT)] = $TMPARRAY;
		}
		//print_r($array);

		foreach ($array as $interface => $ifconfig)
		{
			$TMPARRAY=null;
			foreach($ifconfig as $line)
			{
				if(preg_match("/Administrative Mode: (.+)/", $line, $HITS1))
				{
					$TMPARRAY['mode'] = $HITS1[1];
				}
				if(preg_match("/Operational Mode: (.+)/", $line, $HITS1))
				{
					$TMPARRAY['op_mode'] = $HITS1[1];
				}
				if(preg_match("/Administrative Trunking Encapsulation: (.+)/", $line, $HITS1))
				{
					$TMPARRAY['encapsulation'] = $HITS1[1];
				}
				if(preg_match("/Negotiation of Trunking: (.+)/", $line, $HITS1))
				{
					if($HITS1[1] == "On")
					{
						$TMPARRAY['negotiation'] = 1;
					}
				}
				if(preg_match("/Access Mode VLAN: (\d+)/", $line, $HITS1))
				{
					$TMPARRAY['access_vlan'] = $HITS1[1];
				}
				if(preg_match("/Trunking Native Mode VLAN: (\d+)/", $line, $HITS1))
				{
					$TMPARRAY['native_vlan'] = $HITS1[1];
				}
				if(preg_match("/Voice VLAN: (\d+)/", $line, $HITS1))
				{
					$TMPARRAY['voice_vlan'] = $HITS1[1];
				}
				if(preg_match("/Trunking VLANs Enabled: ALL/", $line, $HITS1))
				{
					$TMPARRAY['all_vlans'] = 1;
				}
			}
			$newarray[$interface]['switchport'] = $TMPARRAY;
		}
		if(isset($newarray))
		{
			return $newarray;
		}
	}
	
}
