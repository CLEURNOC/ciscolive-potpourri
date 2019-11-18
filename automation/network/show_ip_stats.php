<?php
#
# Copyright (c) 2017-2018  Joe Clarke <jclarke@cisco.com>
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


$contents = file_get_contents("/home/jclarke/cached_ip_stats.dat");

$contents = trim($contents);
$stats = explode(" ", $contents);

$total = $stats[0] + $stats[1];
$p4 = ($stats[0] / $total) * 100;
$p6 = ($stats[1] / $total) * 100;

$p4 = number_format($p4, 2);
$p6 = number_format($p6, 2);

$g4 = ($stats[0] / (1000*1000*1000));
$g6 = ($stats[1] / (1000*1000*1000));

$mtime = date ("F d Y H:i:s", filemtime("/home/jclarke/cached_ip_stats.dat"));
?>
<html>
<head>
  <link href="/c3.css" rel="stylesheet" type="text/css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.0/jquery.min.js"></script>
  <script src="/d3.min.js" charset="utf-8"></script>
  <script src="/c3.min.js"></script>
  <script>
setTimeout("location.reload(true);", 300000);
  </script>
  <style type="text/css">
.c3-grid line {
	stroke: none;
}

.c3-axis-x > path.domain, .tick > line[x2="-6"] {
	visibility: hidden;
}

.c3 svg {
	font-size: 16pt;
}

.DeviceTable { table-layout: fixed; }

  </style>
</head>
<body>
<h1 style="text-align: center">IPv4 / IPv6 Traffic Ratio</h1>
<div style="text-align: right; font-size: 10pt;"><b>Last Updated: <?=$mtime?></b></div>
  <div id="chart_div" class="rChart uvcharts"></div>
  <div align="center" style="margin-top: 10px; font-size: 18pt; font-weight: bold;">% of Traffic</div>
  <script language="javascript">
var chart = c3.generate({
	bindto: '#chart_div',
	bar: {
		width: 40,
		units: ' %'

	},
	padding: {
		left: 120
	},
	color: {
		pattern: ['#006666', '#666699']
	},
	data: {
	        x: 'x',
		columns: [
			['x', 'IPv4 Traffic', 'IPv6 Traffic'],
			['value', <?=$p4?>, <?=$p6?>],
		],
		type: 'bar',
		labels: {
			format: {
				value: function (v, id, i, j) { return v + "%"; }
			}
		},
		color: function(inColor, data) {
			var colors = ['#006666', '#666699']
			if (data.index !== undefined) {
				return colors[data.index];
			}

			return inColor;
		}
	},
	axis: {
		rotated: true,
		x: {
			type: 'category'
		}
	},
	legend: {
		show: false
	}
});
</script>

    <table class="DeviceTable" align="center" border="1"
					      cellpadding="2" cellspacing="2" width="40%" style="margin-top: 20px;">
      <tr>
	<th>Protocol</th>
	<th>Total Gigabytes</th>
      </tr>
      <tr>
	<td align="left">IPv4</td>
	<td align="right"><?=number_format($g4, 2, '.', ' ')?> GB</td>
      </tr>
      <tr>
	<td align="left">IPv6</td>
	<td align="right"><?=number_format($g6, 2, '.', ' ')?> GB</td>
      </tr>
    </table>
</body>
</html>
