<?php
#
# Copyright (c) 2017-2023  Joe Clarke <jclarke@cisco.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


$contents = file_get_contents("/home/jclarke/dhcp_scope_stats.dat");

$sarr = json_decode($contents, true);
$scopes = array();

foreach ($sarr as $k => $v) {
	$scopes[$k] = $v['perc'];
}

arsort($scopes, SORT_NUMERIC);
$mtime = date ("F d Y H:i:s", filemtime("/home/jclarke/dhcp_scope_stats.dat"));
?>
<html>
<head>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/c3/0.4.18/c3.min.css" integrity="sha256-rp5Udclt95vV/qBRPHck2jUp/0xytxZgbHCCVRqV9vc=" crossorigin="anonymous" />
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.0/jquery.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/d3/3.5.17/d3.min.js" integrity="sha256-dsOXGNHAo/syFnazt+KTBsCQeRmlcW1XKL0bCK4Baec=" crossorigin="anonymous"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/c3/0.4.18/c3.min.js" integrity="sha256-rx6BHKxiLgSA2BslVk0Gq+bclIxvxBm4eDKxvpS+7wI=" crossorigin="anonymous"></script>
  <script>
setTimeout("location.reload(true);", 600000);
  </script>
</head>
<body>
<h1 style="text-align: center">DHCP Scope Statistics</h1>
<div style="text-align: right; font-size: 10pt;"><b>Last Updated: <?=$mtime?></b></div>
  <table border="0" style="/*table-layout: fixed*/" align="center" width="100%">
    <tbody>
<?php
$max = 3;
$i = 0;
$topn = 9;
foreach ($scopes as $scope => $perc) {
	if ($i % $max == 0) {
		echo "<tr>\n";
	}
	echo "<td style=\"text-align: center; width: 33%; font-size: 14pt;\">\n";
	echo "<div id=\"chart_div_$i\"></div>\n";
	echo "$scope\n";
	echo "</td>\n";
	$i++;
	if ($i % $max == 0) {
		echo "</tr>\n";
	}
	if (!isset($_GET['show_all']) && $i == $topn) {
		break;
	}
}
?>
    </tbody>
  </table>
  <script language="javascript">
<?php
$i = 0;
foreach ($scopes as $scope => $perc) {
?>
var chart<?=$i?> = c3.generate({
	bindto: '#chart_div_<?=$i?>',
	data: {
		columns: [
			['<?=$scope?>', <?=$perc?>]
	        ],
	        type: 'gauge'
        },
	gauge: { },
	color: {
		pattern: ['#60B044', '#F6C600', '#FF0000'],
		threshold: {
			values: [75, 90]
		}
	},
	size: {
		height: 180
	}
});
<?php
	$i++;
}
?>
</script>
<?php
if (!isset($_GET['show_all'])) {
?>
<p style="text-align: left; font-size: 9pt;"><a href="<?=$_SERVER['PHP_SELF']?>?show_all=1">Show All</a></p>
<?php
} else {
?>
<p style="text-align: left; font-size: 9pt;"><a href="<?=$_SERVER['PHP_SELF']?>">Show Top 9</a></p>
<?php
}
?>

</body>
</html>
