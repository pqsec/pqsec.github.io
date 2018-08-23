#!/bin/bash -e

curl https://raw.githubusercontent.com/pages-themes/cayman/master/_layouts/default.html --output _layouts/default.html
patch -d _layouts -p1 < default_layout.patch
