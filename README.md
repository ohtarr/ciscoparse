# ciscoparse
Cisco Configuration Parser

Cisco configuration parser designed to be simple to use.  Simply feed it specific show commands and it will parse and output usable results.

The "input_data" method takes raw SHOW commands from cisco devices and stores them in the INPUT property.  The "update" method triggers any and all parsing and stores
results in the "output" property for use.

example use:
$cp = new \ohtarr\CiscoParse();
$cp->input_data($SHRUN,"run");
$cp->input_data($SHINT,"interfaces");
$cp->input_data($SHVER,"version");
$cp->input_data($SHINV,"inventory");
//$cp->update();  This is ran automatically when you input_data.
print_r($cp->output);
