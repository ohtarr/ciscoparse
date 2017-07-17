<?php

/**
 * cisco_nxos_parse.php.
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
 * @copyright 2017 @authors
 * @license   http://www.gnu.org/copyleft/lesser.html The GNU LESSER GENERAL PUBLIC LICENSE, Version 3.0
 */

namespace ohtarr;

class CiscoNxosParse
{
	public $input = [
		"run" 			=>	"",
		"version" 		=>	"",
		"inventory"		=>	"",
		"cdp"			=>	"",
		"lldp"			=>	"",
		"interfaces"	=>	"",
		"stp"			=>	"",
	];
	//public $interfaces = [];
	public $output = [];

	public function __construct()
	{

	}

	public function __destruct()
	{

	}

	public function input_data($data,$cmdtype)
	{
		if(array_key_exists($cmdtype,$this->input))
		{
			$this->input[$cmdtype] = $data;
		}
	}

	public function update()
	{
		$this->output = array();
		if($this->input['run'])
		{
			$this->output['system']['hostname'] = $this->parse_run_to_hostname();
			$this->output['system']['usernames'] = $this->parse_run_to_usernames();
			$this->output['system']['domain'] = $this->parse_run_to_domain();
			$this->output['system']['nameservers'] = $this->parse_run_to_name_servers();
			$this->output['ips'] = $this->parse_run_to_ips();
			$this->output['interfaces'] = $this->parse_run_to_interfaces();
			$this->output['system']['mgmt'] = $this->parse_run_to_mgmt_interface();
			$this->output['system']['vrfs'] = $this->parse_run_to_vrfs();
			$this->output['system']['ntp'] = $this->parse_run_to_ntp();
		}

		if($this->input['version'])
		{
			$this->output['system']['hostname'] = $this->parse_version_to_hostname();
			$this->output['system']['uptime'] = $this->parse_version_to_uptime();
			$this->output['system']['model'] = $this->parse_version_to_model();
			$this->output['system']['os'] = $this->parse_version_to_ios();
			$this->output['system']['ram'] = $this->parse_version_to_ram();
			$this->output['system']['serial'] = $this->parse_version_to_serial();
			$this->output['system']['license'] = $this->parse_version_to_license();
			$this->output['system']['confreg'] = $this->parse_version_to_confreg();
		}

		if($this->input['inventory'])
		{
			$this->output['system']['inventory'] = $this->parse_inventory();
			$this->output['system']['serial'] = $this->parse_inventory_to_serial();
		}

		if($this->input['cdp'])
		{
			
		}

		if($this->input['lldp'])
		{
			
		}

		if($this->input['interfaces'])
		{
			
		}

		if($this->input['stp'])
		{
			
		}

	}

	function netmask2cidr($netmask)
	{
		$bits = 0;
		$netmask = explode(".", $netmask);

		foreach($netmask as $octect)
			$bits += strlen(str_replace("0", "", decbin($octect)));
		return $bits;
	}

	function cidr2network($ip, $cidr)
	{
		$network = long2ip((ip2long($ip)) & ((-1 << (32 - (int)$cidr))));
		return $network;
	}

	public function parse_run_to_usernames()
	{
		$reg1 = "/^username (\S+).*/m";
		$reg2 = "/privilege (\d+)/m";
		$reg3 = "/secret (\d+) (\S+)/m";

		//find all usernames lines
		if(preg_match_all($reg1, $this->input['run'], $HITS))
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

	public function parse_run_to_hostname()
	{
		$reg1 = "/^hostname (\S+)/m";

		//find hostname line
		if(preg_match_all($reg1, $this->input['run'], $HITS))
		{
			//print_r($HITS);
			return $HITS[1][0];
		}
	}

	public function parse_run_to_domain()
	{
		$reg1 = "/^ip domain-name (\S+)/m";
		$reg2 = "/^ip domain name (\S+)/m";
		if(preg_match_all($reg1, $this->input['run'], $HITS))
		{
			$domain = $HITS[1][0];
		}
		if(preg_match_all($reg2, $this->input['run'], $HITS))
		{
			$domain = $HITS[1][0];
		}
		return $domain;
	}

	public function parse_run_to_name_servers()
	{
		$reg1 = "/^ip name-server (\S+)/m";
		if(preg_match_all($reg1, $this->input['run'], $HITS))
		{
			foreach($HITS[1] as $key => $server)
			{
				//print_r($HITS);
				$servers[] = $server;
			}
		}
		return $servers;
	}

	public function parse_run_to_vrfs()
	{
		$reg = "/vrf definition (\S+)/";
		if(preg_match_all($reg, $this->input['run'], $HITS, PREG_SET_ORDER))
		{
			foreach($HITS as $vrf)
			{
				$vrfs[] = $vrf[1];
			}
		}
		return $vrfs;
	}

	public function parse_run_to_aaa()
	{
	
	}
	
	public function parse_run_to_ntp()
	{
		$reg = "/ntp server (\S+)/";
		$reg2 = "/ntp server vrf (\S+) (\S+)/";
		$reg3 = "/ntp source (\S+)/";
		if(preg_match_all($reg, $this->input['run'], $HITS, PREG_SET_ORDER))
		{
			//print_r($HITS);
			foreach($HITS as $ntp1)
			{
				$ntp['servers'][] = $ntp1[1];
			}
		} 
		if (preg_match_all($reg2, $this->input['run'], $HITS2, PREG_SET_ORDER)) {
			//print_r($HITS2);
			foreach($HITS2 as $ntp2)
			{
				//$ntp[] = $ntp2[2];
				$ntp['servers'][$ntp2[2]]['vrf'] = $ntp2[1];
			}
		}
		if (preg_match($reg3, $this->input['run'], $HITS3)) {
			//print_r($HITS3);
			$ntp['sourceint'] = $HITS3[1];
		}
		
		//print_r($ntp);
		return $ntp;
	}
	
	public function parse_run_to_policymap()
	{

	}

	public function parse_version_to_uptime()
	{
		$reg1 = "/uptime is (.+)/m";
		$reg2 = "/(\d+) year/m";
		$reg3 = "/(\d+) week/m";
		$reg4 = "/(\d+) day/m";
		$reg5 = "/(\d+) hour/m";
		$reg6 = "/(\d+) minute/m";

		if(preg_match_all($reg1, $this->input['version'], $HITS))
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

	public function parse_version_to_model()
	{
			if (preg_match('/.*isco\s+(WS-\S+)\s.*/', $this->input['version'], $reg))
			{
			$model = $reg[1];

			return $model;
		}
		if (preg_match('/.*isco\s+(OS-\S+)\s.*/', $this->input['version'], $reg))
		{
			$model = $reg[1];

			return $model;
		}
		if (preg_match('/.*ardware:\s+(\S+),.*/', $this->input['version'], $reg))
		{
			$model = $reg[1];

			return $model;
		}
		if (preg_match('/.*ardware:\s+(\S+).*/', $this->input['version'], $reg))
		{
			$model = $reg[1];

			return $model;
		}
		if (preg_match('/^[c,C]isco\s(\S+)\s\(.*/m', $this->input['version'], $reg))
		{
			$model = $reg[1];

			return $model;
		}
	}
	
	
	public function parse_version_to_ios()
	{
		$reg1 = "/Cisco (IOS) Software/m";
		$reg2 = "/Cisco (IOS XE) Software/m";
		if (preg_match($reg1, $this->input['version'], $HITS1))
		{
			$os['type'] = $HITS1[1];
		}
		if (preg_match($reg2, $this->input['version'], $HITS2))
		{
			$os['type'] = $HITS2[1];
		}
		$reg3 = '/System image file is "\S+:\/{0,1}(\S+)"/m';
		if (preg_match($reg3, $this->input['version'], $HITS3))
		{
			$os['version'] = $HITS3[1];
		}
		$reg4 = '/Compiled \S+ (\S+)/';
		if (preg_match($reg4, $this->input['version'], $HITS4))
		{
			$os['date'] = $HITS4[1];
		}		
		return $os;
	}
	
	public function parse_version_to_license()
	{
		$reg1 = "/License Level: (\S+)/";
		if (preg_match($reg1, $this->input['version'], $HITS1))
		{
			$license[$HITS1[1]]['current'] = $HITS1[1];
			$reg2 = "/License Type: (\S+)/";
			if (preg_match($reg2, $this->input['version'], $HITS2))
			{
				$license[$HITS1[1]]['type'] = $HITS2[1];
			}
			$reg3 = "/Next reload license Level: (\S+)/";
			if (preg_match($reg3, $this->input['version'], $HITS3))
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
			if (preg_match($reg, $this->input['version'], $HITS))
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

	public function parse_version_to_confreg()
	{
		$reg = "/Configuration register is (\S+)/";
		if (preg_match($reg, $this->input['version'], $HITS1))
		{
			$confreg = $HITS1[1];
		}
		return $confreg;
	}
	
	public function parse_version_to_ram()
	{
		$reg1 = "/with (\d+\S|\d+\S\/\d+\S) bytes of memory/m";
		if (preg_match($reg1, $this->input['version'], $HITS1))
		{
			$ram = $HITS1[1];
		}
		return $ram;
	}

	public function parse_version_to_hostname()
	{
		$reg1 = "/(\S+) uptime/";
		if (preg_match($reg1, $this->input['version'], $HITS1))
		{
			$hostname = $HITS1[1];
		}
		return $hostname;
	}


	public function parse_version_to_serial()
	{
		$reg1 = "/^Processor board ID (\S+)/m";
		if (preg_match($reg1, $this->input['version'], $HITS1))
		{
			$serial = $HITS1[1];
		}
		return $serial;
	}
	
	function parse_run_to_ips()
	{
		$reg1 = "/ip address (\d+.\d+.\d+.\d+) (\d+.\d+.\d+.\d+)/";
		
		foreach(explode("\n", $this->input['run']) as $line)
		{
			if (preg_match($reg1, $line, $HITS1))
			{
				$ips[$HITS1[1]]['network'] = $this->cidr2network($HITS1[1],$this->netmask2cidr($HITS1[2]));
				$ips[$HITS1[1]]['mask'] = $HITS1[2];
				$ips[$HITS1[1]]['cidr'] = $this->netmask2cidr($HITS1[2]);
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

	function parse_run_to_interfaces()
	{
		$LINES = explode("\n", $this->input['run']); 
		$INT = null;
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
					$INTARRAY[$INT]['raw'] = $INTCFG;

					$INTLINES = explode("\n",$INTCFG);
					foreach($INTLINES as $INTLINE)
					{
						if(preg_match("/shutdown/m", $INTLINE, $HITS1))
						{
							$INTARRAY[$INT]['shutdown'] = 1;
						}
						if(preg_match("/description (.*)/m", $INTLINE, $HITS1))
						{
							$INTARRAY[$INT]['description'] = $HITS1[1];
						}
						if(preg_match("/Ethernet/",$INT) || preg_match("/Port-channel/",$INT))
						{
							if(!preg_match("/no switchport/m",$INTLINE))
							{
								if(preg_match("/switchport mode (\D+)$/m", $INTLINE, $HITS1))
								{
									//print "match!\n";
									$INTARRAY[$INT]['switchport']['mode'] = $HITS1[1];
								}
								/*
								if(!preg_match("/switchport mode (\D+)/m", $INTLINE, $HITS1))
								{
									//print "no match!\n";
									$INTARRAY[$INT]['switchport']['mode'] = "dynamic";
								}
								/**/
								if(preg_match("/switchport trunk native vlan (\d+)/m", $INTLINE, $HITS1))
								{
									$INTARRAY[$INT]['switchport']['native_vlan'] = $HITS1[1];
								}
								if(preg_match("/switchport access vlan (\d+)/m", $INTLINE, $HITS1))
								{
									$INTARRAY[$INT]['switchport']['access_vlan'] = $HITS1[1];
								}
								if(preg_match("/switchport voice vlan (\d+)/m", $INTLINE, $HITS1))
								{
									$INTARRAY[$INT]['switchport']['voice_vlan'] = $HITS1[1];
								}
							}
							//print "$INTCFG";
							if(preg_match("/speed (\S+)/", $INTLINE, $HITS1))
							{
								$INTARRAY[$INT]['speed'] = $HITS1[1];
							}
							if(preg_match("/duplex (\S+)/", $INTLINE, $HITS1))
							{
								$INTARRAY[$INT]['duplex'] = $HITS1[1];
							}
						}
						if(preg_match("/bandwidth (\d+)/", $INTLINE, $HITS1))
						{
							$INTARRAY[$INT]['bandwidth'] = $HITS1[1];
						}
						if(preg_match("/vrf forwarding (\S+)/", $INTLINE, $HITS1))
						{
							$INTARRAY[$INT]['vrf'] = $HITS1[1];
						}
						if(preg_match("/ip address (\d+.\d+.\d+.\d+) (\d+.\d+.\d+.\d+)( secondary|)/", $INTLINE, $HITS1))
						{
							$INTARRAY[$INT]['ip'][$HITS1[1]]['mask'] = $HITS1[2];
							$INTARRAY[$INT]['ip'][$HITS1[1]]['cidr'] = $this->netmask2cidr($HITS1[2]);
							$INTARRAY[$INT]['ip'][$HITS1[1]]['network'] = $this->cidr2network($HITS1[1],$this->netmask2cidr($HITS1[2]));
							if($HITS1[3])
							{
								$INTARRAY[$INT]['ip'][$HITS1[1]]['secondary'] = 1;
							}
						}
						if(preg_match("/ip address (dhcp|negotiated)/", $INTLINE, $HITS1))
						{
							$INTARRAY[$INT]['ip'][$HITS1[1]] = 1;
						}
						if(preg_match_all("/ip helper-address (\S+)/m", $INTLINE, $HITS1))
						{
							foreach($HITS1[1] as $helper)
							{
								$INTARRAY[$INT]['helper'][] = $helper;
							}
						}
						if(preg_match("/standby version (\d)/m", $INTLINE, $HITS1))
						{
							$INTARRAY[$INT]['hsrp']['version'] = $HITS1[1];
						}
						if(preg_match_all("/standby (\d+) ip (\S+)/m", $INTLINE, $HITS1))
						{
							foreach($HITS1[1] as $key => $group)
							{
								$INTARRAY[$INT]['hsrp']['group'][$group]['ip'] = $HITS1[2][$key];
							}
						}
						if(preg_match_all("/standby (\d+) priority (\d+)/m", $INTLINE, $HITS1))
						{
							foreach($HITS1[1] as $key => $group)
							{
								$INTARRAY[$INT]['hsrp']['group'][$group]['priority'] = $HITS1[2][$key];
							}
						}
						if(preg_match("/ip mtu (\S+)/m", $INTLINE, $HITS1))
						{
							$INTARRAY[$INT]['ipmtu'] = $HITS1[1];
						}
						if(preg_match("/ip tcp adjust-mss (\S+)/m", $INTLINE, $HITS1))
						{
							$INTARRAY[$INT]['adjustmss'] = $HITS1[1];
						}
						if(preg_match("/service-policy output (\S+)/", $INTLINE, $HITS1))
						{
							$INTARRAY[$INT]['service-policy'] = $HITS1[1];
						}
					}
					$INTCFG = "";
				}
				if (preg_match("/^interface (\S+)/", $LINE, $HITS))
				{
					$INT = $HITS[1];
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
		return $INTARRAY;
	}

	public function parse_run_to_mgmt_interface()
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

		foreach($regs as $reg){
			if (preg_match($reg, $this->input['run'], $HITS))
			{
				//print_r($HITS);
				//$SOURCES[$HITS[1]] = $SOURCES[$HITS[1]]++;
				$SOURCES[$HITS[1]]++;
			}
		}
		array_multisort($SOURCES,SORT_DESC);
		//print_r($SOURCES);
		foreach($SOURCES as $SOURCE => $COUNT)
		{
			$return['interface'] = $SOURCE;
			break;
		}
		foreach($this->interfaces[$SOURCE]['ip'] as $ip => $mask)
		{
			$return['ip'] = $ip;
			break;
		}
		return $return;
	}

	public function parse_inventory()
	{
		$reg = '/NAME:\s*(\S.*\S),\s*DESCR:\s*(.*)\nPID:\s*(\S.*\S)\s*,\s*VID:\s*(\S.*\S)\s*,\s*SN:\s*(\S.*\S)/';
		if (preg_match_all($reg, $this->input['inventory'], $HITS, PREG_SET_ORDER))
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

	public function parse_inventory_to_serial()
	{
		$reg = '/NAME:\s*(\S.*\S),\s*DESCR:\s*(.*)\nPID:\s*(\S.*\S)\s*,\s*VID:\s*(\S.*\S)\s*,\s*SN:\s*(\S.*\S)/';
		if (preg_match_all($reg, $this->input['inventory'], $HITS, PREG_SET_ORDER))
		{
			foreach($HITS as $key => $entity)
			{
				$sn = $HITS[$key][5];
				break;
			}
			return $sn;
		}
	}
}
