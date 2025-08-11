System_file;

! To use this extension, define a word array for each actor that should have
! topics to talk about. Add 0 or more topics to the array, and end it with
! the value TM_END. Give each talkable NPC a property talk_array with the
! name of their array as the value.
!
! A talk topic has the following form:
!
! STATUS [ID]* TOPIC PLAYERSAYS NPCSAYS [FLAGREF|ACTIVATEREF|INACTIVATEREF|ROUTINE|STRING]*
!
! or:
!
! TM_MAYBE_ADD_LIST FLAGREF|ROUTINE ARRAY
!
! [] = Optional
! * = can be more than one
!
! STATUS is either 0 ( = TM_INACTIVE = not active) or
!   30 ( = TM_ACTIVE  = active) or TM_STALE (has been used).
! ID is a number (300-600) which can be used as a reference to 
!   activate/inactivate a topic in code or using an ACTIVATEREF or 
!   INACTIVATEREF in a talk array. Note that IDs are local to the NPC - two 
!   different NPCs can use the same ID for different topics without risk of 
!   confusion.
! TOPIC is a string or routine for the topic name
! PLAYERSAYS can be on any of these forms (ROUTSTR means a routine or string):
!    * ROUTSTR
!    * TM_ADD_BEFORE ROUTSTR ROUTSTR
!    * TM_ADD_AFTER ROUTSTR ROUTSTR
!    * TM_ADD_BEFORE_AND_AFTER ROUTSTR ROUTSTR ROUTSTR
!    I.e. you can add a routine or string to run/print BEFORE the player's
!    line, AFTER the player's line, or both. To mute the player's line, give
!    it the value TM_NO_LINE
! NPCSAYS is a string or routine for what the NPC replies. To mute it, give
!    it the value TM_NO_LINE
! FLAGREF is a number 32-299 for a flag to be set (In order to use this,
!    you must include ext_flags.h before including ext_talk_menu.h)
! ACTIVATEREF is the keyword TM_ACTIVATE followed be either a 
!    topic ID (300-600) or a relative reference to a topic (1 to 20, or 
!    -1 to -20) that is activated by this topic. 1 means the next topic,
!    2 the topic after that etc. The keyword TM_ACTIVATE can be omitted, 
!    unless the reference number is negative. Note that a negative number in
!    an array has to be enclosed in parentheses, or the compiler will get 
!    confused. ALso note that When a topic is picked by the player, it gets 
!    the status TM_STALE, and the only way to change it from this 
!    status is to call `ReActivateTopic` or `ReInactivateTopic`.
! INACTIVATEREF is the keyword TM_INACTIVATE followed by either a 
!    topic ID (300-600) or a relative reference to a topic (1 to 20, or 
!    -1 to -20) that is inactivated by this topic.
! ROUTINE is a routine to be run. In this routine, the global variable
!    current_talker refers to the NPC being talked to.
! STRING is a string to be printed.
!
! Whenever a routine is used for PLAYERSAYS, NPCSAYS or ROUTINE, it can set
! the global talk_menu_talking to false to end the conversation after the 
! current topic. When doing this, you may want to use ROUTINE to print a 
! suitable message about why the conversation ended.
!
! TM_MAYBE_ADD_LIST is a special value which means: If it's followed by a
!    flag reference, and that flag is set, OR it's followed by a routine and
!    that routine returns true, the topic list held in the sub-array specified 
!    will be added. A few restrictions apply: 
!        (1) The sub-array may not contain a TM_MAYBE_ADD_LIST token.
!        (2) a relative ACTIVATEREF or INACTIVATEREF in the base array may not
!            refer to a topic within a sub-array or past a TM_MAYBE_ADD_LIST
!            token.
!        (3) a relative ACTIVATEREF or INACTIVATEREF in a sub-array may only
!            refer to a topic within the same sub-array.
! FLAGREF is a flag number, normally between 32 and 299. If the flag is set,
!    the sub-array is included.
! ROUTINE is a routine to decide if the sub-array should be included. It may
!    not randomize a result, and it may not alter the state of the game.
! ARRAY is the name of an array (referred to as a sub-array above), which
!    works as a normal talk array. 
!
! Example of an array giving Linda one active topic (Weather), which will
! activate the next topic (Heat) and the topic with ID 300 (Herself), and if
! you ask about Heat, she'll just end the conversation without answering.
!
! [ EnoughTalk; talk_menu_talking = false; ];
!
! Array talk_array_linda -->
!   0 300 "Herself" "Tell me more about yourself!" "I'm just an average girl."
!   30 "Weather" "How do you like the weather?" "It's too hot for me." 1 300
!   0 "Heat" "Say, don't you like hot weather?" TM_NO_LINE EnoughTalk
!          "Linda looks upset and turns away."
!   TM_END;
!
! Object Linda "Linda"
!   with talk_array talk_array_linda,
!   ...
!
! If you find that you need more topic IDs, or more flags, you can define which
! number should be the lowest one to be considered an ID (32-600, default is
! 300) by defining the constant TM_FIRST_ID, i.e. to get 100 more IDs and
! 100 less flags, do this before including ext_talk_menu.h:
!
! Constant TM_FIRST_ID = 200; ! 32-199 are now flags, while 200-600 are IDs
!
! Should you find that you need both a lot of flags and a lot of topic IDs,
! you can:
!
! 1. Make sure all routines you refer to in your talk_array are defined *after*
!    including puny.h.
! 2: Set the constant TM_LAST_ID to 2000. Instead of 300-600, you can now use
!    300-2000 for topic IDs.
! 3. In conjuction with this, you can also use TM_FIRST_ID to define where
!    flags end and topic IDs begin.
!
! Apart from activating topics using ACTIVATEREFs and INACTIVATEREFs in a 
! talk_array, you can also use these routines:
! ActivateTopic(NPC, topic) => true for success, false for fail
!   Activates the topic, unless it's stale.
! ReActivateTopic(NPC, topic) => true for success, false for fail
!   Activates the topic, regardless of its status.
! InactivateTopic(NPC, topic) => true for success, false for fail
!   Inactivates the topic, unless it's stale.
! ReInactivateTopic(NPC, topic) => true for success, false for fail
!   Inactivates the topic, regardless of its status.
! GetTopicStatus(NPC, topic) => topic status (TM_INACTIVE, TM_ACTIVE, TM_STALE)
!   Returns the status of the topic.
!
! If you call these routines with DEBUG defined *and* RUNTIME_ERRORS > 0, you
! will be notified whenever a problem is detected. As usual, use
! RUNTIME_ERRORS = 2 to get the maximum amount of information. (This is the
! default when compiling in DEBUG mode)
!
! By default, you can assign the same ID to multiple topics and use this to
! activate or inactivate multiple topics at once. If you're not using this
! option, you can set talk_menu_multi_mode to false, and gain some
! performance.

Constant EXT_TALK_MENU = 1;

! Define constants needed if compiled with the standard library
#Ifndef RUNTIME_ERRORS;
Constant RUNTIME_ERRORS = 2;
#Endif;
#Ifndef RTE_MINIMUM;
Constant RTE_MINIMUM = 0;
Constant RTE_NORMAL = 1;
Constant RTE_VERBOSE = 2;
#Endif;
#Iftrue RUNTIME_ERRORS > RTE_MINIMUM;
Constant TM_ERR = "^[Talk_menu error #";
#Endif;
#Ifdef DEBUG;
	#Ifndef TM_ERR;
	Constant TM_ERR = "^[Talk_menu error #";
	#Endif;
#Endif;

#Ifndef talk_array;
Property individual talk_array;
#Endif;

Global current_talker;

Default TM_FIRST_ID = 300;
Default TM_LAST_ID = 600;

#Iftrue TM_FIRST_ID < 32;
Message fatalerror "*** ERROR: ext_talk_menu: TM_FIRST_ID must be in the range 32 to TM_LAST_ID ***";
#Endif;
#Iftrue TM_FIRST_ID > TM_LAST_ID;
Message fatalerror "*** ERROR: ext_talk_menu: TM_FIRST_ID must be in the range 32 to TM_LAST_ID ***";
#Endif;



#Ifdef TM_MSG_TOPICS_DEPLETED;
#Ifdef TM_MSG_EXIT;
Constant TM_SKIP_MSG_EXIT;
#Endif;
#Endif;

#Ifndef TM_SKIP_MSG_EXIT;
Constant TM_REUSABLE_MSG_EXIT "With that, you politely end the conversation.";
#Endif;

#Ifndef TM_MSG_YOU;
Constant TM_MSG_YOU "You";
#Endif;

#Ifndef TM_MSG_TALK_ABOUT_WHAT;
[ TM_MSG_TALK_ABOUT_WHAT;
	print "Talk to ", (the) current_talker, " about:^";
];
#Endif;
#Ifndef TM_MSG_TOPICS_DEPLETED;
Constant TM_MSG_TOPICS_DEPLETED TM_REUSABLE_MSG_EXIT;
#Endif;
#Ifndef TM_MSG_EXIT;
Constant TM_MSG_EXIT TM_REUSABLE_MSG_EXIT;
#Endif;
#Ifndef TM_MSG_NO_TOPICS;
Constant TM_MSG_NO_TOPICS "Right now, you wouldn't know what to talk about.";
#Endif;
#Ifndef TM_MSG_EXIT_OPTION;
Constant TM_MSG_EXIT_OPTION "[ENTER] End conversation";
#Endif;

#Ifndef TM_MSG_PAGE_OPTION;
Constant TM_MSG_PAGE_OPTION "[N] Next page";
#Endif;
#Ifv5;
#Ifndef TM_MSG_EXIT_OPTION_SHORT;
Constant TM_MSG_EXIT_OPTION_SHORT "[ENTER] End"; ! This + TM_MSG_PAGE_OPTION_SHORT should be 18 characters or less
#Endif;
#Ifndef TM_MSG_PAGE_OPTION_SHORT;
Constant TM_MSG_PAGE_OPTION_SHORT "[N]ext"; ! This + TM_MSG_EXIT_OPTION_SHORT should be 18 characters or less
#Endif;
#Endif;

#Ifndef TMPrintLine;
[TMPrintLine p_actor p_array p_line;
	! Routine to print a line, by the player or an NPC. Define your own version as needed.
	if(p_array-->p_line == TM_NO_LINE)
		rfalse;
	if(p_actor == player)
		_TMPrintMsg(TM_MSG_YOU, true);
	else
		print (The) p_actor;
	print ": ~";
	_TMCallOrPrint(p_array, p_line, true); ! Can be called as _TMCallOrPrint(p_array, p_line, true); if you don't want it to print the newline, or omit third parameter to print a newline
	"~";
];
#Endif;

Constant TM_INACTIVE 0;
Constant TM_ACTIVATE 27;
Constant TM_INACTIVATE 28;
Constant TM_MAYBE_ADD_LIST 29;
Constant TM_ACTIVE 30;
Constant TM_STALE 31;
Constant TM_END 26;

Constant TM_NO_LINE 1; ! Can be used instead of a player's line or an actor's line ONLY!
Constant TM_ADD_BEFORE 2; ! Can be used directly after subject
Constant TM_ADD_AFTER 3; ! Can be used directly after subject
Constant TM_ADD_BEFORE_AND_AFTER 4; ! Can be used directly after subject

Global talk_menu_talking = false;
Global talk_menu_multi_mode = true;
Global clr_talk_menu = CLR_CURRENT;

[ _TMPrintMsg p_msg p_no_newline;
	if(metaclass(p_msg) == Routine) {
		p_msg();
		rtrue;
	}
	print (string) p_msg;
	if(p_no_newline == false) new_line;
];

[ _TMCallOrPrint p_array p_index p_no_newline;
	_TMPrintMsg(p_array-->p_index, p_no_newline);
];

[ _SetTopic p_topic p_array p_value _index _val _find_topic _base _curr_id _success _stash_array;
	! p_topic is 1-20: Act on topic number P_TOPIC, counting from p_array
	! p_topic is 300-600: Act on topic with ID = P_TOPIC.
	! p_topic is (-600)-(-300): Act on topic with ID = -P_TOPIC. If p_value is
	!   TM_ACTIVE or TM_INACTIVE, set the topic status even if it's currently
	!   in status TM_STALE.
	! p_array: Start from this index in the talk_menu array and work forward,
	!   until a TM_NPC token is found.
	! p_value is TM_ACTIVE: Set the topic to active, if it's currently in
	!   status TM_INACTIVE or TM_ACTIVE. If p_topic is negative, set
	!   it to active even if the topic is in status TM_STALE.
	! p_value is TM_INACTIVE: Set the topic to inactive, if it's currently in
	!   status TM_INACTIVE or TM_ACTIVE. If p_topic is negative, set
	!   it to inactive even if the topic is in status TM_STALE.
	! p_value is 1: Return the current status of the topic. Return true if not found.
	! Return true if setting succeeded, false if not.
	!
	! Examples:
	! Activate the next topic from index 123:
	!   _SetTopic(1, 123, TM_ACTIVE);
	! Activate topic with ID 301, starting from index 123:
	!   _SetTopic(301, 123, TM_ACTIVE);
	! Reactivate topic with ID 301, starting from index 123:
	!   _SetTopic(-301, 123, TM_ACTIVE);
	! Inactivate topic with ID 301, starting from index 123:
	!   _SetTopic(301, 123, TM_INACTIVE);
	_find_topic = p_topic;
	if(_find_topic < 0)
		_find_topic = -_find_topic;
	_index--;
	while(true) {
		_index++;
		if(p_topic < 0 && p_topic >= -21) {
			_index = _index - 2;
		}
		_val = p_array-->_index;
		if(_val == TM_INACTIVE or TM_ACTIVE or TM_STALE) {
			if(_find_topic < 29) {
				if(_find_topic-- == 1) jump _tm_found_topic;
				continue;
			}
			_base = _index;
			while(true) { ! Loop over a list of topic IDs
				_index++;
				_curr_id = p_array-->_index;
				if(_curr_id < TM_FIRST_ID || _curr_id > TM_LAST_ID) {
					_index = _index + 2; ! This is a string or routine, no more IDs here
					break;
				}
				if(_curr_id == _find_topic) {
					_success = true;
					_index = _base;
._tm_found_topic;
					if(p_value == 1)
						return p_array-->_index;
					if(_val ~= TM_STALE || p_topic < -21) {
						p_array-->_index = p_value;
					}
					if(_find_topic < 29 || talk_menu_multi_mode == false) {
						rtrue;
					}
					_index = _index + 3;
					break;

				}
			}
		} else if(_val == TM_MAYBE_ADD_LIST or TM_END) {
			if(_val == TM_MAYBE_ADD_LIST) {
				if(_find_topic < 29) {
					! Signal failure, as the topic was not found
					if(p_value == 1) rtrue;
					rfalse;
				}
				_index = _index + 2;
				_curr_id = p_array-->_index;
				_stash_array = p_array + _index + _index;
				p_array = _curr_id;
				_index = -1;
			} else  { ! _val == TM_END
				if(_find_topic < 29) {
					! Signal failure, as the topic was not found
					if(p_value == 1) rtrue;
					rfalse;
				}
				if(_stash_array) {
					p_array = _stash_array;
					_index = 0;
					_stash_array = 0;
				} else {
					! The topic wasn't found, or we are in multi mode
					if(p_value == 1) rtrue; ! When trying to read a status, reaching the end means failure 
					return _success; ! The topic wasn't found, or we are in multi mode
				}
			}
		}
	}
];

[ ActivateTopic p_npc p_topic p_array;
	if(p_array == 0) p_array = p_npc.talk_array;
	p_array = _SetTopic(p_topic, p_array, TM_ACTIVE);
	#Ifdef DEBUG;
	#Iftrue RUNTIME_ERRORS > RTE_MINIMUM;
		if(p_array == 0) {
	#Iftrue RUNTIME_ERRORS == RTE_VERBOSE;
			print (string) TM_ERR,"3: Could not activate topic ", p_topic, " for NPC ", (name) p_npc, "]^";
	#Ifnot;
			print (string) TM_ERR,"3]^";
	#Endif;
			rfalse;
		}
	#Endif;
	#Endif;
	return p_array;
];

[ ReActivateTopic p_npc p_topic;
	return ActivateTopic(p_npc, -p_topic);
];

[ InactivateTopic p_npc p_topic p_array;
	if(p_array == 0) p_array = p_npc.talk_array;
	p_array = _SetTopic(p_topic, p_array, TM_INACTIVE);
	#Ifdef DEBUG;
	#Iftrue RUNTIME_ERRORS > RTE_MINIMUM;
		if(p_array == 0) {
	#Iftrue RUNTIME_ERRORS == RTE_VERBOSE;
			print (string) TM_ERR,"3: Could not inactivate topic ", p_topic, " for NPC ", (name) p_npc, "]^";
	#Ifnot;
			print (string) TM_ERR,"3]^";
	#Endif;
			rfalse;
		}
	#Endif;
	#Endif;
	return p_array;
];

[ ReInactivateTopic p_npc p_topic;
	return InActivateTopic(p_npc, -p_topic);
];

[ GetTopicStatus p_npc p_topic p_array;
	if(p_array == 0) p_array = p_npc.talk_array;
	return _SetTopic(p_topic, p_array, 1);
];


#Ifv5;
Array TenDashes static -> "----------";
[ FastDashes p_dashes;
	while(p_dashes > 10) {
		@print_table TenDashes 10 1;
		p_dashes = p_dashes - 10;
	}
	@print_table TenDashes p_dashes 1;
];
#Endif;

Array _TMLines --> 10;

#Ifv5;
#Ifdef PUNYINFORM_MAJOR_VERSION;
[ RunTalk p_npc _array _i _j _n _val _height _width _offset _count _more _has_split _add_msg _stash_array _old_fg;
#Ifnot;
[ RunTalk p_npc _array _i _j _n _val _height _width _offset _count _more _has_split _add_msg _stash_array;
#Endif;
#Ifnot;
! Target is z3 
[ RunTalk p_npc _array _i _j _n _val _offset _count _more _add_msg _stash_array;
#Endif;
	talk_menu_talking = true;
	current_talker = p_npc;
#Iftrue RUNTIME_ERRORS > RTE_MINIMUM;
	if(~~(p_npc provides talk_array)) {
#Iftrue RUNTIME_ERRORS == RTE_VERBOSE;
		print_ret (string) TM_ERR,"1: Object ", p_npc, " (", (name) p_npc, ") doesn't provide talk_array]";
#Ifnot;
		print_ret (string) TM_ERR,"1]";
#Endif;
	}
#Endif;
	! Prepare upper window
#Ifv5;
	! Find out or guess the height of the screen
	_height = HDR_SCREENHLINES->0;
	_width = HDR_SCREENWCHARS->0;
	if(_height < 2) _height = 25;
	! Figure out best height for upper window. Note that _height now changes
	! meaning, from holding the height of the screen to holding the height of
	! the upper window
	if(_height > 31) _height = 16;
	else if(_height > 13) @log_shift _height (-1) -> _height; !Division by 2
	else _height = 7;
#Endif;

	! Print all valid lines to say

._tm_restart_talk_after_line;

	_offset = 0;

._tm_restart_talk;

	! Restore basic talk array
	_array = p_npc.talk_array;
	_stash_array = 0;
	
	_count = 0;
	_more = 0;
	_i = -1;
	_n = 0;
	while(true) {
		_i++;
		_val = _array-->_i;
		if(_val == TM_END) {
			if(_stash_array) {
				_array = _stash_array;
				_i = 0;
				_stash_array = 0;
			} else {
				break;
			}
		} else if(_val == TM_MAYBE_ADD_LIST) {
			_i++;
			_val = _array-->_i;
			_i++;
#Ifdef EXT_FLAGS;
			if(_val > 0 && _val < TM_FIRST_ID)
				_val = FlagIsSet(_val);
			else
				_val = _val();
#Ifnot;
			_val = _val();
#Endif;
			if(_val) {
				_stash_array = _array + _i + _i;
				_array = _array-->_i;
				_i = -1;
			}
		} else if(_val == TM_INACTIVE or TM_STALE) 
			_i = _i + 3;
		else if(_val == TM_ACTIVE) {
#Ifv5;
			if(_count >= _height - 6) { _more = 1; break; }
			_n++;
			if(_n <= _offset) continue;
			_count++;
!			print "Talk to ", (the) p_npc, " about:^";
			if(_count == 1) {
				_has_split = true;
				@split_window _height;
				@erase_window 1;
				DrawStatusLine();
				@set_window 1;
				@set_cursor 2 1;
#Ifdef PUNYINFORM_MAJOR_VERSION;
				if(clr_on) {
					_old_fg = clr_fg;
					ChangeFgColour(clr_talk_menu);
				}
#Endif;
				_TMPrintMsg(TM_MSG_TALK_ABOUT_WHAT);
			}
			print "  ", _count % 10, ": ";
#Ifnot;
			if(_count >= 8) { _more = 1; break; }
			_n++;
			if(_n <= _offset) continue;
			_count++;
!			print "Talk to ", (the) p_npc, " about:^";
			if(_count == 1) {
				_TMPrintMsg(TM_MSG_TALK_ABOUT_WHAT);
			}
			print "  ", _count, ": ";
#Endif;
			(_TMLines - 2)-->_count = _array + _i + _i; ! Store the start of the line
			_i++;
			_val = _array-->_i;
			while(_val >= TM_FIRST_ID && _val <= TM_LAST_ID) {
				! An ID was found
				_i++;
				_val = _array-->_i;
			}
			_TMCallOrPrint(_array, _i);
		}
	}
	if(_n == 0) {
#Ifv5;
		@set_window 0;
#Endif;
		_val = TM_MSG_NO_TOPICS;
!		"Right now, you wouldn't know what to talk about.";
		if(_j)
			_val = TM_MSG_TOPICS_DEPLETED;
!			"With that, you politely end the conversation.";
		_TMPrintMsg(_val);
#Ifv5;
		jump _tm_end_of_talk;
#Ifnot;
		rtrue;
#Endif;
	}

#Ifv5;
	_i = _height - 1;
	@set_cursor _i 1;
	FastDashes(_width);
	_i = _height - 3;
	@set_cursor _i 1;
#Endif;
	_i = TM_MSG_EXIT_OPTION;
	_j = TM_MSG_PAGE_OPTION;
#Ifv5;
	if(_width < 39) {
		_i = TM_MSG_EXIT_OPTION_SHORT;
		_j = TM_MSG_PAGE_OPTION_SHORT;
	}
#Endif;
	_TMPrintMsg(_i, true);

	if(_more || _offset) {
		print "  ";
		_TMPrintMsg(_j, true);
	}
	new_line;
#Ifdef PUNYINFORM_MAJOR_VERSION;
#Ifv5;
	if(clr_on)
		ChangeFgColour(_old_fg);
#Endif;
#Endif;

	! Ask player to choose a line to say
._askAgain;

	_j = 0;
	while(_j == 0) {
#IfV5;
		@read_char 1 -> _val;

		if(_val == 13 or 'q' or 'Q' or 'x' or 'X') {
			@set_window 0;
			_TMPrintMsg(TM_MSG_EXIT);
!			"With that, you politely end the conversation.";
			jump _tm_end_of_talk;
		}
		if(_val == 'n' or 'N' or 130) {
			if(_more) {
				_offset = _offset + _height - 6;
				jump _tm_restart_talk;
			}
			else if(_offset) {
				_offset = 0;
				jump _tm_restart_talk;
			}
		}
		_j = _val - 48;
		if(_j == 0) _j = 10;
#IfNot;
		! This is v3
		PrintMsg(MSG_PROMPT);
		@sread buffer parse;
		num_words = parse->1;

		if(num_words == 0) {
			_TMPrintMsg(TM_MSG_EXIT);
!			"With that, you politely end the conversation.";
			rtrue;
		}
		_val = buffer->1;
		if(_val == 'n') {
			if(_more) {
				_offset = _offset + 8;
				jump _tm_restart_talk;
			}
			else if(_offset) {
				_offset = 0;
				jump _tm_restart_talk;
			}
		}
		_j = TryNumber(1);
#EndIf;
	}

	if(_j < 1 || _j > _count) jump _askAgain;

	! Print the line and reply

	_array = (_TMLines - 2)-->_j;
	_array-->0 = TM_STALE;
	_i = 1;
	_val = _array-->_i;

	while(_val >= TM_FIRST_ID && _val <= TM_LAST_ID) {
		! An ID was found
		_i++;
		_val = _array-->_i;
	}

	_i++;

#Ifv5;
	@set_window 0;
#Endif;

	_add_msg = _array-->_i;
	if(_add_msg == TM_ADD_BEFORE or TM_ADD_AFTER or TM_ADD_BEFORE_AND_AFTER)
		_i++;
	if(_add_msg == TM_ADD_BEFORE or TM_ADD_BEFORE_AND_AFTER) {
		_TMCallOrPrint(_array, _i);
		_i++;
	}
	TMPrintLine(player, _array, _i);
	_i++;
	if(_add_msg == TM_ADD_AFTER or TM_ADD_BEFORE_AND_AFTER) {
		_TMCallOrPrint(_array, _i);
		_i++;
	}
	TMPrintLine(p_npc, _array, _i);

	! Apply effects

	_j = _i;
	while(true) {
		_j++;
		_val = _array-->_j;
!		print "Performing action ", _val, " at pos ", _j, "^";
		if(_val == TM_INACTIVE or TM_ACTIVE or TM_STALE or TM_END or TM_MAYBE_ADD_LIST) {
			! No more effects to process
			break;
		}

		if(_val > 0) {
			if(_val == TM_INACTIVATE) {
				! Next value is an absolute or relative reference to a topic to inactivate
				_j++;
				_val = _array-->_j;
				! TODO: Check valid range here!
				if(_val >= TM_FIRST_ID) {
					! An absolute ID for a topic to inactivate
					InActivateTopic(p_npc, _val);
				} else {
					! A relative ID for a topic to inacivate
					if(_val < 0) 
						_val--;
					InActivateTopic(p_npc, _val, _array + _j + _j);
				}
				continue;
			}
			if(_val == TM_ACTIVATE) {
				_j++;
				_val = _array-->_j;
				! TODO: Check valid range here!
			}
			if(_val < 30) {
				! A relative reference to a topic to activate
				if(_val < 0) 
					_val--;
				ActivateTopic(p_npc, _val, _array + _j + _j);
				continue;
			}
			#Ifdef EXT_FLAGS;
			if(_val < TM_FIRST_ID) {
				! A flag to set
				SetFlag(_val);
				continue;
			}
			#Endif;
			if(_val <= TM_LAST_ID) {
				! An absolute ID for a topic to activate
				ActivateTopic(p_npc, _val);
				continue;
			}
		}
		#Ifdef DEBUG;
			#Iftrue RUNTIME_ERRORS > RTE_MINIMUM;
				if(metaclass(_val) ~= Routine or String) {
					#Iftrue RUNTIME_ERRORS == RTE_VERBOSE;
						print_ret (string) TM_ERR,"2: Action ", _val, " was not understood for ", (name) p_npc, "]";
					#Ifnot;
						print_ret (string) TM_ERR,"2]";
					#Endif;
				}
			#Endif;
		#Endif;
		! A routine to call or a string to print
		_TMCallOrPrint(_array, _j);
	}

	if(talk_menu_talking) {
		new_line;
		jump _tm_restart_talk_after_line;
	}
._tm_end_of_talk;
#Ifv5;
	if(_has_split) {
		@erase_window 1;
		@split_window 0;
		@set_window 0;
		#Ifdef PUNYINFORM_MAJOR_VERSION;
			statusline_current_height = 0;
		#Ifnot;
			gg_statuswin_cursize = 0;
		#Endif;
	}
#Endif;
	talk_menu_talking = false;
	rtrue;
];

[ TalkSub;
#Ifdef PUNYINFORM_MAJOR_VERSION;
   if (noun==player) { PrintMsg(MSG_TELL_PLAYER); rtrue; }
   if (~~(noun provides talk_array)) { second = noun; PrintMsg(MSG_SHOW_DEFAULT); rtrue; }
#Ifnot;
   if (noun==player) { L__M(##Tell, 1, noun); rtrue; }
   if (~~(noun provides talk_array)) { L__M(##Show, 2, second); rtrue; }
#Endif;
   RunTalk(noun);
   AfterRoutines();
];

Verb 'talk' 'converse' 'interview' 'interrogate'
	* 'to'/'with' creature                      ->Talk
	* creature                                  ->Talk;

#Ifdef DEBUG;
#Ifdef FLAG_COUNT;
Constant TM_MAX_FLAG = FLAG_COUNT;
#Ifnot;
Constant TM_MAX_FLAG = 0;
#Endif;

[ _TMErrorContext p_topic p_element p_value;
#Ifv5;
	style bold;
#Endif;
	print "*** ERROR! ***^";
#Ifv5;
	style roman;
#Endif;
	print "Topic: ", p_topic,", ";
	print "Array element: ", p_element,", ";
	print "Value: ", p_value,"^";
	print "Error: ";
];

Constant TM_ERR_NOT_FOUND "Target topic not found.";

[ _CheckTMArray p_npc p_array _v _v0 _i _topic _backtopics _subs;
	_i--;
	_backtopics = 1;
	while(_v ~= TM_END) {
		_v = p_array --> (++_i);
		if(_v == TM_MAYBE_ADD_LIST) {
			_subs++;
			print "Examining sub-array ", _subs,".^";
			_v = p_array --> (++_i);
			if((_v < 32 || _v > TM_MAX_FLAG) && metaclass(_v) ~= Routine) {
				_TMErrorContext(_topic, _i, _v); 
				"Value after TM_MAYBE_ADD_LIST is not a valid flag# or a routine address.";
			}
			_v = p_array --> (++_i);
			_CheckTMArray(p_npc, _v);
			_backtopics = 1;
		} else if(_v == TM_ACTIVE or TM_INACTIVE or TM_STALE) {
			_topic++;
			_backtopics--;
!			print "  Topic #", _topic, "^";
			! Iterate past any IDs specified for this topic
			while(true) {
				_v = p_array --> (++_i);
				if(_v < TM_FIRST_ID || _v > TM_LAST_ID) break; 
			}
			if(metaclass(_v) ~= Routine or String) {
				_TMErrorContext(_topic, _i, _v); 
				"Topic name is not a string or routine.";
			}
			_v = p_array --> (++_i);
			if(_v == TM_ADD_BEFORE_AND_AFTER or TM_ADD_BEFORE) {
				_v0 = p_array --> (++_i);
				if(metaclass(_v0) ~= Routine or String) {
					_TMErrorContext(_topic, _i, _v0); 
					"Item to be printed BEFORE player line is not a string or routine.";
				}
				_v0 = p_array --> (++_i);
			} else if(_v == TM_ADD_AFTER) {
				_v0 = p_array --> (++_i);
			} else
				_v0 = _v;
			if(_v0 ~= TM_NO_LINE && metaclass(_v0) ~= Routine or String) {
				_TMErrorContext(_topic, _i, _v0); 
				"Player line is not TM_NO_LINE, nor a string or routine.";
			}
			if(_v == TM_ADD_BEFORE_AND_AFTER or TM_ADD_AFTER) {
				_v0 = p_array --> (++_i);
				if(metaclass(_v0) ~= Routine or String) {
					_TMErrorContext(_topic, _i, _v0); 
					"Item to be printed AFTER player line is not a string or routine.";
				}
			}
			_v = p_array --> (++_i);
			if(_v ~= TM_NO_LINE && metaclass(_v) ~= Routine or String) {
				_TMErrorContext(_topic, _i, _v); 
				"NPC line is not TM_NO_LINE, nor a string or routine.";
			}
			! Process line effects
			while(true) {
				_v = p_array --> (++_i);
				if(_v == TM_ACTIVE or TM_INACTIVE or TM_STALE or 
						TM_MAYBE_ADD_LIST or TM_END) {
					_i--;
					break;
				}
				if(metaclass(_v) == Routine or String || (_v > 31 && _v <= TM_MAX_FLAG))
					continue;
				! Has to be an activate/inactivate topic
				if(_v == TM_ACTIVATE or TM_INACTIVATE)
					_v = p_array --> (++_i);
				if(_v >= TM_FIRST_ID && _v <= TM_LAST_ID) {
					if(GetTopicStatus(p_npc, _v) == true) {
						_TMErrorContext(_topic, _i, _v); 
						print_ret (string) TM_ERR_NOT_FOUND;
					}
					continue;
				}
				if(_v >= -20 && _v <= -1) {
					if(_backtopics > _v) {
						_TMErrorContext(_topic, _i, _v); 
						print_ret (string) TM_ERR_NOT_FOUND;
					}
					continue;
				}
				if(_v > 0 && _v <= 20) {
					if(GetTopicStatus(p_npc, _v, p_array + _i + _i) == true) {
						_TMErrorContext(_topic, _i, _v); 
						print_ret (string) TM_ERR_NOT_FOUND;
					}
					continue;
				}
				_TMErrorContext(_topic, _i, _v);
				if(0 < 1)
				"Unknown value.";
			}
			
		}
	}
	"Array end (", _topic, " topics)";		
];

[ _ExamineTMObj p_obj;
	print "=== Examining talk_menu for ", (the) p_obj, " ===^";
	if(p_obj provides talk_array && p_obj.talk_array ~= 0) {
		_CheckTMArray(p_obj, p_obj.talk_array);
	} else {
		"ERROR: Lacks talk_array value.";
	}
];

[ TMTestSub _o _showed_any;
	if(noun) {
		_ExamineTMObj(noun);
	} else {
		objectloop(_o provides talk_array && _o.talk_array ~= 0) {
			if(_showed_any) new_line;
			_ExamineTMObj(_o);
			_showed_any = true;
		}
	}
];

Verb meta 'tmtest'
	* noun -> TMTest
	*      -> TMTest;
#Endif;
