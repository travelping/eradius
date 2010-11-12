-ifndef(_ERADIUS_DICT).
-define(_ERADIUS_DICT, true).
%%%-------------------------------------------------------------------
%%% File        : eradius_dict.hrl
%%% Author      : tobbe@bluetail.com
%%% Description : Dictionary definitions.
%%% Created     : 25 Sep 2003 by tobbe@bluetail.com
%%%
%%% $Id: eradius_dict.hrl,v 1.1 2003/10/27 23:39:40 etnt Exp $
%%%-------------------------------------------------------------------

-type attribute_id() :: integer() | {integer(), integer()}.

-record(attribute, {
	  id         :: attribute_id(),
	  type       :: atom(),
	  name       :: string(),
	  enc = no   :: atom()
	 }).


-record(vendor, {
	  type       :: integer(),
	  name       :: string()
	 }).

-record(value, {
	  id         :: integer(),
	  name       :: string()
}).

-endif.

