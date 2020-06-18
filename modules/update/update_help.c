/* NeoStats - IRC Statistical Services 
** Copyright (c) 1999-2008 Adam Rutter, Justin Hammond, Mark Hetherington
** http://www.neostats.net/
**
**  Portions Copyright (c) 2000-2008 ^Enigma^
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
**  USA
**
** NeoStats CVS Identification
** $Id: cs_help.c 3077 2007-01-06 06:27:35Z Fish $
*/

#include "neostats.h"

const char *update_help_set_updateurl[] = 
{
	"UPDATEURL <URL>",
	"The URL to use to check for updates of NeoStats or its Modules",
	NULL
};

const char *update_help_set_updateenabled[] = 
{
	"UPDATEENABLE <on/off>",
	"Enable Automatic Update Notifications of new NeoStats Versions and its Modules",
	NULL
};