# pam_hipchat

## Summary

This module sends a notification to a hipchat room after a successful login.

## Build

Pre-build, you need to install the curl dev packages.

   * gcc -fPIC -fno-stack-protector -c src/pam_hipchat.c
   * ld -lcurl -x --shared -o pam_hipchat.so pam_hipchat.o

## Install

This will depend somewhat on your distro's config but something like:

cp pam_hipchat.so /lib/security/

## Configure

This module is meant to be used as a session module.  That ensures that the user in question has been authenticated and authorized.  I suggest you configure it in the specific service configs that you want to notify, not in common-session or the like.  Adding a like like the below to 'ssh' or 'login' or the like will work just fine.

session        optional pam_hipchat.so server=https://<your team>.hipchat.com/v2/room/<room ID>/notification auth_token=<room auth token>

The full list of config items is:

   * server=        the URL to the notification API for the room you want
   * auth_token=    the room notification authentication token
   * notify         wheather or not to notify the room with the mesage
   * from=          the username to use when the notification happens.  If this needs to include a space you need to enclose the whole thing in brackets, a la [from=PAM Notifier]
