#!/bin/sh

svn2cl -i --break-before-msg --reparagraph --linelen=120 -r HEAD:1 $*
