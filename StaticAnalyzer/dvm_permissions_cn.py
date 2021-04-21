
# Androguard is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androguard is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androguard.  If not, see <http://www.gnu.org/licenses/>.

# frameworks/base/core/res/AndroidManifest.xml
# ######################################### PERMISSIONS ###################
# flake8: noqa
DVM_PERMISSIONS = {
    'MANIFEST_PERMISSION': {
        'SEND_SMS': ['dangerous', '发送短信', '允许应用程序发送短信。恶意应用程序可能会在没有您的确认的情况下发送消息，从而对您造成金钱损失。'],
        'CALL_PHONE': ['dangerous', '直接拨打电话号码', '允许应用程序拨打电话号码，而不需要您的干预。恶意应用程序可能会导致您的电话账单上出现意外拨打电话记录。不过，这不允许应用程序呼叫紧急号码。'],
        'RECEIVE_SMS': ['dangerous', '接收短信', '允许应用程序接收和处理短信。恶意应用程序可能会监视你的消息，或者在不向你显示的情况下删除它们。'],
        'RECEIVE_MMS': ['dangerous', '接收彩信', '允许应用程序接收和处理彩信消息。恶意应用程序可能会监视你的消息，或者在不向你显示的情况下删除它们。'],
        'READ_SMS': ['dangerous', '阅读短信或彩信', '允许应用程序读取存储在您的手机或SIM卡里的短信。恶意应用程序可能会读取您的机密信息。'],
        'WRITE_SMS': ['dangerous', '编辑短信或彩信', '允许应用程序写入短信到您的手机或SIM卡。恶意应用程序可能会删除您的消息。'],
        'RECEIVE_WAP_PUSH': ['dangerous', '收到WAP推送消息', '允许应用程序接收和处理WAP消息。恶意应用程序可能会监视你的消息，或者在不向你显示的情况下删除它们。'],
        'READ_CONTACTS': ['dangerous', 'read contact data', '允许一个应用程序读取所有的联系人(地址)数据存储在您的手机上。恶意应用程序可以利用这一点将您的数据发送给其他人。'],
        'WRITE_CONTACTS': ['dangerous', 'write contact data', '允许一个应用程序修改联系人(地址)数据存储在您的手机。恶意的应用程序可以使用它来删除或修改您的联系人数据。'],
        'READ_PROFILE': ['dangerous', 'read the user\'s personal profile data', '允许一个程序读取用户的个人资料数据。'],
        'WRITE_PROFILE': ['dangerous', 'write the user\'s personal profile data', '允许应用程序写入(但不读取)用户的个人资料数据。'],
        'READ_SOCIAL_STREAM': ['dangerous', 'read from the user\'s social stream', '允许应用程序读取用户的社交流。'],
        'WRITE_SOCIAL_STREAM': ['dangerous', 'write the user\'s social stream', '允许一个程序写入(但不读取)用户的社交流数据。'],
        'READ_CALENDAR': ['dangerous', 'read calendar events', '允许一个程序读取所有的日历事件存储在您的手机上。恶意应用程序可以使用此功能将您的日历事件发送给其他人。'],
        'WRITE_CALENDAR': ['dangerous', '添加或修改日历事件并向客人发送电子邮件', '允许应用程序添加或更改你的日历上的事件，这可能会发送电子邮件给客人。恶意的应用程序可以用它来删除或修改你的日历事件或给客人发送电子邮件。'],
        'READ_USER_DICTIONARY': ['dangerous', 'read user-defined dictionary', '允许应用程序读取用户可能存储在用户字典中的任何私有单词、名称和短语。'],
        'WRITE_USER_DICTIONARY': ['normal', 'write to user-defined dictionary', '允许应用程序将新单词写入用户字典。'],
        'READ_HISTORY_BOOKMARKS': ['dangerous', 'read Browser\'s history and bookmarks', '允许应用程序读取浏览器访问过的所有url和浏览器的所有书签。'],
        'WRITE_HISTORY_BOOKMARKS': ['dangerous', 'write Browser\'s history and bookmarks', '允许一个应用程序修改浏览器的历史或书签存储在您的手机。恶意的应用程序可以使用它来删除或修改你的浏览器的数据。'],
        'SET_ALARM': ['normal', 'set alarm in alarm clock', '允许应用程序在已安装的闹钟应用程序中设置闹钟。一些闹钟应用程序可能没有实现这个功能。'],
        'ACCESS_FINE_LOCATION': ['dangerous', 'fine (GPS) location', '在可能的情况下，使用精确的定位源，如手机上的全球定位系统。恶意的应用程序可以使用它来确定您的位置，并且可能会消耗额外的电池能量。'],
        'ACCESS_COARSE_LOCATION': ['dangerous', 'coarse (network-based) location', '访问粗糙的定位源，如移动网络数据库，以确定手机的大致位置，在可能的情况下。恶意的应用程序可以使用它来确定您的大致位置。'],
        'ACCESS_MOCK_LOCATION': ['dangerous', 'mock location sources for testing', '创建用于测试的模拟位置源。恶意应用程序可以使用它来覆盖由GPS或网络供应商等实时定位源返回的位置和/或状态。'],
        'ACCESS_LOCATION_EXTRA_COMMANDS': ['normal', 'access extra location provider commands', '访问额外的位置提供程序命令。恶意应用程序可以利用它来干扰GPS或其他定位源的操作。'],
        'INSTALL_LOCATION_PROVIDER': ['signatureOrSystem', '安装位置提供程序的权限', '创建用于测试的模拟位置源。恶意应用程序可以使用它来覆盖由GPS或网络供应商等实时位置源返回的位置和/或状态，或者监视并向外部源报告您的位置。'],
        'INTERNET': ['normal', '完整的互联网接入', '允许应用程序创建网络套接字。'],
        'ACCESS_NETWORK_STATE': ['normal', '查看网络状态', '允许一个程序查看所有网络的状态。'],
        'ACCESS_WIFI_STATE': ['normal', '查看 Wi-Fi 状态', '允许程序查看有关Wi-Fi状态的信息。'],
        'BLUETOOTH': ['normal', 'create Bluetooth connections', '允许应用程序连接到配对的蓝牙设备。'],
        'NFC': ['normal', 'control Near-Field Communication', '允许应用程序与近场通信(NFC)标签，卡和读取器通信。'],
        'USE_SIP': ['dangerous', 'make/receive Internet calls', '允许应用程序使用SIP服务来发出/接收Internet呼叫。'],
        'ACCOUNT_MANAGER': ['signature', 'act as the Account Manager Service', 'Allows an application to make calls to Account Authenticators'],
        'GET_ACCOUNTS': ['dangerous', 'list accounts', 'Allows access to the list of accounts in the Accounts Service.'],
        'AUTHENTICATE_ACCOUNTS': ['dangerous', 'act as an account authenticator', 'Allows an application to use the account authenticator capabilities of the Account Manager, including creating accounts as well as obtaining and setting their passwords.'],
        'USE_CREDENTIALS': ['dangerous', 'use the authentication credentials of an account', 'Allows an application to request authentication tokens.'],
        'MANAGE_ACCOUNTS': ['dangerous', 'manage the accounts list', 'Allows an application to perform operations like adding and removing accounts and deleting their password.'],
        'MODIFY_AUDIO_SETTINGS': ['normal', 'change your audio settings', 'Allows application to modify global audio settings, such as volume and routing.'],
        'RECORD_AUDIO': ['dangerous', 'record audio', 'Allows application to access the audio record path.'],
        'CAMERA': ['dangerous', 'take pictures and videos', 'Allows application to take pictures and videos with the camera. This allows the application to collect images that the camera is seeing at any time.'],
        'VIBRATE': ['normal', 'control vibrator', 'Allows the application to control the vibrator.'],
        'FLASHLIGHT': ['normal', 'control flashlight', 'Allows the application to control the flashlight.'],
        'ACCESS_USB': ['signatureOrSystem', 'access USB devices', 'Allows the application to access USB devices.'],
        'HARDWARE_TEST': ['signature', 'test hardware', 'Allows the application to control various peripherals for the purpose of hardware testing.'],
        'PROCESS_OUTGOING_CALLS': ['dangerous', 'intercept outgoing calls', 'Allows application to process outgoing calls and change the number to be dialled. Malicious applications may monitor, redirect or prevent outgoing calls.'],
        'MODIFY_PHONE_STATE': ['signatureOrSystem', 'modify phone status', 'Allows the application to control the phone features of the device. An application with this permission can switch networks, turn the phone radio on and off and the like, without ever notifying you.'],
        'READ_PHONE_STATE': ['dangerous', '获取通话状态、手机号与设备标识', '允许应用程序访问手机功能的设备。具有此权限的应用程序可以确定该电话的电话号码和序列号、呼叫是否处于活动状态、呼叫所连接的号码等等。'],
        'WRITE_EXTERNAL_STORAGE': ['dangerous', '读取/修改/删除外部存储内容', '允许应用程序写入外部存储器。'],
        'READ_EXTERNAL_STORAGE': ['dangerous', '读取外部存储内容', '允许应用程序从外部存储器读取数据。'],
        'WRITE_SETTINGS': ['dangerous', '修改全局系统设置', '允许程序修改系统的设置数据。恶意的应用程序会破坏你的系统配置。'],
        'WRITE_SECURE_SETTINGS': ['signatureOrSystem', '修改安全系统设置', '允许程序修改系统的安全设置数据。一般应用程序不能使用。'],
        'WRITE_GSERVICES': ['signatureOrSystem', 'modify the Google services map', 'Allows an application to modify the Google services map. Not for use by common applications.'],
        'EXPAND_STATUS_BAR': ['normal', 'expand/collapse status bar', 'Allows application to expand or collapse the status bar.'],
        'GET_TASKS': ['dangerous', 'retrieve running applications', 'Allows application to retrieve information about currently and recently running tasks. May allow malicious applications to discover private information about other applications.'],
        'REORDER_TASKS': ['normal', 'reorder applications running', 'Allows an application to move tasks to the foreground and background. Malicious applications can force themselves to the front without your control.'],
        'CHANGE_CONFIGURATION': ['signatureOrSystem', 'change your UI settings', 'Allows an application to change the current configuration, such as the locale or overall font size.'],
        'RESTART_PACKAGES': ['normal', 'kill background processes', 'Allows an application to kill background processes of other applications, even if memory is not low.'],
        'KILL_BACKGROUND_PROCESSES': ['normal', 'kill background processes', 'Allows an application to kill background processes of other applications, even if memory is not low.'],
        'FORCE_STOP_PACKAGES': ['signature', 'force-stop other applications', 'Allows an application to stop other applications forcibly.'],
        'DUMP': ['signatureOrSystem', 'retrieve system internal status', 'Allows application to retrieve internal status of the system. Malicious applications may retrieve a wide variety of private and secure information that they should never commonly need.'],
        'SYSTEM_ALERT_WINDOW': ['dangerous', 'display system-level alerts', 'Allows an application to show system-alert windows. Malicious applications can take over the entire screen of the phone.'],
        'SET_ANIMATION_SCALE': ['dangerous', 'modify global animation speed', 'Allows an application to change the global animation speed (faster or slower animations) at any time.'],
        'PERSISTENT_ACTIVITY': ['dangerous', 'make application always run', 'Allows an application to make parts of itself persistent, so that the system can\'t use it for other applications.'],
        'GET_PACKAGE_SIZE': ['normal', 'measure application storage space', 'Allows an application to find out the space used by any package.'],
        'SET_PREFERRED_APPLICATIONS': ['signature', 'set preferred applications', 'Allows an application to modify your preferred applications. This can allow malicious applications to silently change the applications that are run, spoofing your existing applications to collect private data from you.'],
        'RECEIVE_BOOT_COMPLETED': ['normal', 'automatically start at boot', 'Allows an application to start itself as soon as the system has finished booting. This can make it take longer to start the phone and allow the application to slow down the overall phone by always running.'],
        'BROADCAST_STICKY': ['normal', 'send sticky broadcast', 'Allows an application to send sticky broadcasts, which remain after the broadcast ends. Malicious applications can make the phone slow or unstable by causing it to use too much memory.'],
        'WAKE_LOCK': ['normal', 'prevent phone from sleeping', 'Allows an application to prevent the phone from going to sleep.'],
        'SET_WALLPAPER': ['normal', 'set wallpaper', 'Allows the application to set the system wallpaper.'],
        'SET_WALLPAPER_HINTS': ['normal', 'set wallpaper size hints', 'Allows the application to set the system wallpaper size hints.'],
        'SET_TIME': ['signatureOrSystem', 'set time', 'Allows an application to change the phone\'s clock time.'],
        'SET_TIME_ZONE': ['signatureOrSystem', 'set time zone', 'Allows an application to change the phone\'s time zone.'],
        'MOUNT_UNMOUNT_FILESYSTEMS': ['dangerous', 'mount and unmount file systems', 'Allows the application to mount and unmount file systems for removable storage.'],
        'MOUNT_FORMAT_FILESYSTEMS': ['dangerous', 'format external storage', 'Allows the application to format removable storage.'],
        'ASEC_ACCESS': ['signature', 'get information on internal storage', 'Allows the application to get information on internal storage.'],
        'ASEC_CREATE': ['signature', 'create internal storage', 'Allows the application to create internal storage.'],
        'ASEC_DESTROY': ['signature', 'destroy internal storage', 'Allows the application to destroy internal storage.'],
        'ASEC_MOUNT_UNMOUNT': ['signature', 'mount/unmount internal storage', 'Allows the application to mount/unmount internal storage.'],
        'ASEC_RENAME': ['signature', 'rename internal storage', 'Allows the application to rename internal storage.'],
        'DISABLE_KEYGUARD': ['normal', '', 'Allows applications to disable the keyguard if it is not secure.'],
        'READ_SYNC_SETTINGS': ['normal', 'read sync settings', 'Allows an application to read the sync settings, such as whether sync is enabled for Contacts.'],
        'WRITE_SYNC_SETTINGS': ['normal', 'write sync settings', 'Allows an application to modify the sync settings, such as whether sync is enabled for Contacts.'],
        'READ_SYNC_STATS': ['normal', 'read sync statistics', 'Allows an application to read the sync stats; e.g. the history of syncs that have occurred.'],
        'WRITE_APN_SETTINGS': ['dangerous', 'write Access Point Name settings', 'Allows an application to modify the APN settings, such as Proxy and Port of any APN.'],
        'SUBSCRIBED_FEEDS_READ': ['normal', 'read subscribed feeds', 'Allows an application to receive details about the currently synced feeds.'],
        'SUBSCRIBED_FEEDS_WRITE': ['dangerous', 'write subscribed feeds', 'Allows an application to modify your currently synced feeds. This could allow a malicious application to change your synced feeds.'],
        'CHANGE_NETWORK_STATE': ['normal', '改变网络连接', '允许应用程序改变网络连接状态。'],
        'CHANGE_WIFI_STATE': ['normal', '修改 Wi-Fi 状态', '允许应用程序连接和断开Wi-Fi接入点，并更改配置的Wi-Fi网络。'],
        'CHANGE_WIFI_MULTICAST_STATE': ['normal', 'allow Wi-Fi Multicast reception', 'Allows an application to receive packets not directly addressed to your device. This can be useful when discovering services offered nearby. It uses more power than the non-multicast mode.'],
        'BLUETOOTH_ADMIN': ['normal', 'bluetooth administration', 'Allows applications to discover and pair bluetooth devices.'],
        'CLEAR_APP_CACHE': ['signatureOrSystem', 'delete all application cache data', 'Allows an application to free phone storage by deleting files in application cache directory. Access is usually very restricted to system process.'],
        'READ_LOGS': ['dangerous', 'read sensitive log data', 'Allows an application to read from the system\'s various log files. This allows it to discover general information about what you are doing with the phone, potentially including personal or private information.'],
        'SET_DEBUG_APP': ['dangerous', 'enable application debugging', 'Allows an application to turn on debugging for another application. Malicious applications can use this to kill other applications.'],
        'SET_PROCESS_LIMIT': ['dangerous', 'limit number of running processes', 'Allows an application to control the maximum number of processes that will run. Never needed for common applications.'],
        'SET_ALWAYS_FINISH': ['dangerous', 'make all background applications close', 'Allows an application to control whether activities are always finished as soon as they go to the background. Never needed for common applications.'],
        'SIGNAL_PERSISTENT_PROCESSES': ['dangerous', 'send Linux signals to applications', 'Allows application to request that the supplied signal be sent to all persistent processes.'],
        'DIAGNOSTIC': ['signature', 'read/write to resources owned by diag', 'Allows an application to read and write to any resource owned by the diag group; for example, files in /dev. This could potentially affect system stability and security. This should ONLY be used for hardware-specific diagnostics by the manufacturer or operator.'],
        'STATUS_BAR': ['signatureOrSystem', 'disable or modify status bar', 'Allows application to disable the status bar or add and remove system icons.'],
        'STATUS_BAR_SERVICE': ['signature', 'status bar', 'Allows the application to be the status bar.'],
        'FORCE_BACK': ['signature', 'force application to close', 'Allows an application to force any activity that is in the foreground to close and go back. Should never be needed for common applications.'],
        'UPDATE_DEVICE_STATS': ['signatureOrSystem', 'modify battery statistics', 'Allows the modification of collected battery statistics. Not for use by common applications.'],
        'INTERNAL_SYSTEM_WINDOW': ['signature', 'display unauthorised windows', 'Allows the creation of windows that are intended to be used by the internal system user interface. Not for use by common applications.'],
        'MANAGE_APP_TOKENS': ['signature', 'manage application tokens', 'Allows applications to create and manage their own tokens, bypassing their common Z-ordering. Should never be needed for common applications.'],
        'INJECT_EVENTS': ['signature', 'press keys and control buttons', 'Allows an application to deliver its own input events (key presses, etc.) to other applications. Malicious applications can use this to take over the phone.'],
        'SET_ACTIVITY_WATCHER': ['signature', 'monitor and control all application launching', 'Allows an application to monitor and control how the system launches activities. Malicious applications may compromise the system completely. This permission is needed only for development, never for common phone usage.'],
        'SHUTDOWN': ['signature', 'partial shutdown', 'Puts the activity manager into a shut-down state. Does not perform a complete shut down.'],
        'STOP_APP_SWITCHES': ['signature', 'prevent app switches', 'Prevents the user from switching to another application.'],
        'READ_INPUT_STATE': ['signature', 'record what you type and actions that you take', 'Allows applications to watch the keys that you press even when interacting with another application (such as entering a password). Should never be needed for common applications.'],
        'BIND_INPUT_METHOD': ['signature', 'bind to an input method', 'Allows the holder to bind to the top-level interface of an input method. Should never be needed for common applications.'],
        'BIND_WALLPAPER': ['signatureOrSystem', 'bind to wallpaper', 'Allows the holder to bind to the top-level interface of wallpaper. Should never be needed for common applications.'],
        'BIND_DEVICE_ADMIN': ['signature', 'interact with device admin', 'Allows the holder to send intents to a device administrator. Should never be needed for common applications.'],
        'SET_ORIENTATION': ['signature', 'change screen orientation', 'Allows an application to change the rotation of the screen at any time. Should never be needed for common applications.'],
        'INSTALL_PACKAGES': ['signatureOrSystem', 'directly install applications', 'Allows an application to install new or updated Android packages. Malicious applications can use this to add new applications with arbitrarily powerful permissions.'],
        'REQUEST_INSTALL_PACKAGES': ['dangerous', 'Allows an application to request installing packages.', 'Malicious applications can use this to try and trick users into installing additional malicious packages.'],
        'CLEAR_APP_USER_DATA': ['signature', 'delete other applications\' data', 'Allows an application to clear user data.'],
        'DELETE_CACHE_FILES': ['signatureOrSystem', 'delete other applications\' caches', 'Allows an application to delete cache files.'],
        'DELETE_PACKAGES': ['signatureOrSystem', 'delete applications', 'Allows an application to delete Android packages. Malicious applications can use this to delete important applications.'],
        'MOVE_PACKAGE': ['signatureOrSystem', 'Move application resources', 'Allows an application to move application resources from internal to external media and vice versa.'],
        'CHANGE_COMPONENT_ENABLED_STATE': ['signatureOrSystem', 'enable or disable application components', 'Allows an application to change whether or not a component of another application is enabled. Malicious applications can use this to disable important phone capabilities. It is important to be careful with permission, as it is possible to bring application components into an unusable, inconsistent or unstable state.'],
        'ACCESS_SURFACE_FLINGER': ['signature', 'access SurfaceFlinger', 'Allows application to use SurfaceFlinger low-level features.'],
        'READ_FRAME_BUFFER': ['signature', 'read frame buffer', 'Allows application to read the content of the frame buffer.'],
        'BRICK': ['signature', 'permanently disable phone', 'Allows the application to disable the entire phone permanently. This is very dangerous.'],
        'REBOOT': ['signatureOrSystem', 'force phone reboot', 'Allows the application to force the phone to reboot.'],
        'DEVICE_POWER': ['signature', 'turn phone on or off', 'Allows the application to turn the phone on or off.'],
        'FACTORY_TEST': ['signature', 'run in factory test mode', 'Run as a low-level manufacturer test, allowing complete access to the phone hardware. Only available when a phone is running in manufacturer test mode.'],
        'BROADCAST_PACKAGE_REMOVED': ['signature', 'send package removed broadcast', 'Allows an application to broadcast a notification that an application package has been removed. Malicious applications may use this to kill any other application running.'],
        'BROADCAST_SMS': ['signature', 'send SMS-received broadcast', 'Allows an application to broadcast a notification that an SMS message has been received. Malicious applications may use this to forge incoming SMS messages.'],
        'BROADCAST_WAP_PUSH': ['signature', 'send WAP-PUSH-received broadcast', 'Allows an application to broadcast a notification that a WAP-PUSH message has been received. Malicious applications may use this to forge MMS message receipt or to replace the content of any web page silently with malicious variants.'],
        'MASTER_CLEAR': ['signatureOrSystem', 'reset system to factory defaults', 'Allows an application to completely reset the system to its factory settings, erasing all data, configuration and installed applications.'],
        'CALL_PRIVILEGED': ['signatureOrSystem', 'directly call any phone numbers', 'Allows the application to call any phone number, including emergency numbers, without your intervention. Malicious applications may place unnecessary and illegal calls to emergency services.'],
        'PERFORM_CDMA_PROVISIONING': ['signatureOrSystem', 'directly start CDMA phone setup', 'Allows the application to start CDMA provisioning. Malicious applications may start CDMA provisioning unnecessarily'],
        'CONTROL_LOCATION_UPDATES': ['signatureOrSystem', 'control location update notifications', 'Allows enabling/disabling location update notifications from the radio. Not for use by common applications.'],
        'ACCESS_CHECKIN_PROPERTIES': ['signatureOrSystem', 'access check-in properties', 'Allows read/write access to properties uploaded by the check-in service. Not for use by common applications.'],
        'PACKAGE_USAGE_STATS': ['signature', 'update component usage statistics', 'Allows the modification of collected component usage statistics. Not for use by common applications.'],
        'BATTERY_STATS': ['signature', 'modify battery statistics', 'Allows the modification of collected battery statistics. Not for use by common applications.'],
        'BACKUP': ['signatureOrSystem', 'control system back up and restore', 'Allows the application to control the system\'s back-up and restore mechanism. Not for use by common applications.'],
        'BIND_APPWIDGET': ['signatureOrSystem', 'choose widgets', 'Allows the application to tell the system which widgets can be used by which application. With this permission, applications can give access to personal data to other applications. Not for use by common applications.'],
        'CHANGE_BACKGROUND_DATA_SETTING': ['signature', 'change background data usage setting', 'Allows an application to change the background data usage setting.'],
        'GLOBAL_SEARCH': ['signatureOrSystem', '', 'This permission can be used on content providers to allow the global search system to access their data. Typically it used when the provider has some permissions protecting it (which global search would not be expected to hold), and added as a read-only permission to the path in the provider where global search queries are performed. This permission can not be held by regular applications; it is used by applications to protect themselves from everyone else besides global search.'],
        'GLOBAL_SEARCH_CONTROL': ['signature', '', ''],
        'SET_WALLPAPER_COMPONENT': ['signatureOrSystem', '', ''],
        'ACCESS_CACHE_FILESYSTEM': ['signatureOrSystem', 'access the cache file system', 'Allows an application to read and write the cache file system.'],
        'COPY_PROTECTED_DATA': ['signature', 'Allows to invoke default container service to copy content. Not for use by common applications.', 'Allows to invoke default container service to copy content. Not for use by common applications.'],
        'C2D_MESSAGE': ['signature', 'Allows cloud to device messaging', 'Allows the application to receive push notifications.'],
        'RECEIVE': ['signature', 'C2DM permissions', 'Permission for cloud to device messaging.'],
        'ADD_VOICEMAIL': ['dangerous', 'add voicemails into the system', 'Allows an application to add voicemails into the system.'],
        'ACCEPT_HANDOVER': ['dangerous', '', 'Allows a calling app to continue a call which was started in another app.  An example is a video calling app that wants to continue a voice call on the user\'s mobile network.'],
        'ACCESS_NOTIFICATION_POLICY': ['normal', '', 'Marker permission for applications that wish to access notification policy.'],
        'ANSWER_PHONE_CALLS': ['dangerous', '', 'Allows the app to answer an incoming phone call.'],
        'BIND_ACCESSIBILITY_SERVICE': ['signature', '', 'Must be required by an AccessibilityService, to ensure that only the system can bind to it.'],
        'BIND_AUTOFILL_SERVICE': ['signature', '', 'Must be required by a AutofillService, to ensure that only the system can bind to it.'],
        'BIND_CARRIER_MESSAGING_SERVICE': ['signature', '', 'The system process that is allowed to bind to services in carrier apps will have this permission.'],
        'BIND_CARRIER_SERVICES': ['signature', '', 'The system process that is allowed to bind to services in carrier apps will have this permission. Carrier apps should use this permission to protect their services that only the system is allowed to bind to.'],
        'BIND_CHOOSER_TARGET_SERVICE': ['signature', '', 'Must be required by a ChooserTargetService, to ensure that only the system can bind to it'],
        'BIND_CONDITION_PROVIDER_SERVICE': ['signature', '', 'Must be required by a ConditionProviderService, to ensure that only the system can bind to it'],
        'BIND_DREAM_SERVICE': ['signature', '', 'Must be required by an DreamService, to ensure that only the system can bind to it.'],
        'BIND_INCALL_SERVICE': ['signature', '', 'Must be required by a InCallService, to ensure that only the system can bind to it.'],
        'BIND_MIDI_DEVICE_SERVICE': ['signature', '', 'Must be required by an MidiDeviceService, to ensure that only the system can bind to it.'],
        'BIND_NFC_SERVICE': ['signature', '', 'Must be required by a HostApduService or OffHostApduService to ensure that only the system can bind to it.'],
        'BIND_NOTIFICATION_LISTENER_SERVICE': ['signature', '', 'Must be required by an NotificationListenerService, to ensure that only the system can bind to it.'],
        'BIND_PRINT_SERVICE': ['signature', '', 'Must be required by a PrintService, to ensure that only the system can bind to it.'],
        'BIND_QUICK_SETTINGS_TILE': ['signatureOrSystem', '', 'Allows an application to bind to third party quick settings tiles.'],
        'BIND_REMOTEVIEWS': ['signature', '', 'Must be required by a RemoteViewsService, to ensure that only the system can bind to it.'],
        'BIND_SCREENING_SERVICE': ['signature', '', 'Must be required by a CallScreeningService, to ensure that only the system can bind to it.'],
        'BIND_TELECOM_CONNECTION_SERVICE': ['signature', '', 'Must be required by a ConnectionService, to ensure that only the system can bind to it.'],
        'BIND_TEXT_SERVICE': ['signature', '', 'Must be required by a TextService (e.g. SpellCheckerService) to ensure that only the system can bind to it.'],
        'BIND_TV_INPUT': ['signature', '', 'Must be required by a TvInputService to ensure that only the system can bind to it.'],
        'BIND_VISUAL_VOICEMAIL_SERVICE': ['signature', '', 'Must be required by a link VisualVoicemailService to ensure that only the system can bind to it.'],
        'BIND_VOICE_INTERACTION': ['signature', '', 'Must be required by a VoiceInteractionService, to ensure that only the system can bind to it.'],
        'BIND_VPN_SERVICE': ['signature', '', 'Must be required by a VpnService, to ensure that only the system can bind to it.'],
        'BIND_VR_LISTENER_SERVICE': ['signature', '', 'Must be required by an VrListenerService, to ensure that only the system can bind to it.'],
        'BLUETOOTH_PRIVILEGED': ['signatureOrSystem', '', 'Allows applications to pair bluetooth devices without user interaction, and to allow or disallow phonebook access or message access. This is not available to third party applications.'],
        'BODY_SENSORS': ['dangerous', '', 'Allows an application to access data from sensors that the user uses to measure what is happening inside his/her body, such as heart rate.'],
        'CAPTURE_AUDIO_OUTPUT': ['signatureOrSystem', '', 'Allows an application to capture audio output.'],
        'CAPTURE_SECURE_VIDEO_OUTPUT': ['normal', '', 'Allows an application to capture secure video output.'],
        'CAPTURE_VIDEO_OUTPUT': ['normal', '', 'Allows an application to capture video output.'],
        'FOREGROUND_SERVICE': ['normal', '', 'Allows a regular application to use Service.startForeground'],
        'GET_ACCOUNTS_PRIVILEGED': ['signatureOrSystem', '', 'Allows access to the list of accounts in the Accounts Service.'],
        'INSTALL_SHORTCUT': ['normal', '', 'Allows an application to install a shortcut in Launcher.'],
        'INSTANT_APP_FOREGROUND_SERVICE': ['signatureOrSystem', '', 'Allows an instant app to create foreground services.'],
        'LOCATION_HARDWARE': ['normal', '', 'Allows an application to use location features in hardware, such as the geofencing api.'],
        'MANAGE_DOCUMENTS': ['signature', '', 'Allows an application to manage access to documents, usually as part of a document picker.'],
        'MANAGE_OWN_CALLS': ['normal', '', 'Allows a calling application which manages it own calls through the self-managed'],
        'MEDIA_CONTENT_CONTROL': ['normal', '', 'Allows an application to know what content is playing and control its playback.'],
        'NFC_TRANSACTION_EVENT': ['normal', '', 'Allows applications to receive NFC transaction events.'],
        'READ_CALL_LOG': ['dangerous', '', 'Allows an application to read the user\'s call log.'],
        'READ_PHONE_NUMBERS': ['dangerous', '', 'Allows read access to the device\'s phone number(s). This is a subset of the capabilities granted by'],
        'READ_VOICEMAIL': ['signature', '', 'Allows an application to read voicemails in the system.'],
        'REQUEST_COMPANION_RUN_IN_BACKGROUND': ['normal', '', 'Allows a companion app to run in the background.'],
        'REQUEST_COMPANION_USE_DATA_IN_BACKGROUND': ['normal', '', 'Allows a companion app to use data in the background.'],
        'REQUEST_DELETE_PACKAGES': ['normal', '', 'Allows an application to request deleting packages.'],
        'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS': ['normal', '', 'Permission an application must hold in order to use Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS.'],
        'SEND_RESPOND_VIA_MESSAGE': ['signatureOrSystem', '', 'Allows an application (Phone) to send a request to other applications to handle the respond-via-message action during incoming calls.'],
        'TRANSMIT_IR': ['normal', '', 'Allows using the device\'s IR transmitter, if available.'],
        'UNINSTALL_SHORTCUT': ['normal', '', 'Don\'t use this permission in your app. This permission is no longer supported.'],
        'USE_BIOMETRIC': ['normal', '', 'Allows an app to use device supported biometric modalities.'],
        'USE_FINGERPRINT': ['normal', 'allow use of fingerprint', 'This constant was deprecated in API level 28. Applications should request USE_BIOMETRIC instead'],
        'WRITE_CALL_LOG': ['dangerous', '', 'Allows an application to write (but not read) the user\'s call log data.'],
        'WRITE_VOICEMAIL': ['signature', '', 'Allows an application to modify and remove existing voicemails in the system.'],
        'ACCESS_BACKGROUND_LOCATION': ['dangerous', 'access location in background', 'Allows an app to access location in the background. If you\'re requesting this permission, you must also request either'],
        'ACCESS_MEDIA_LOCATION': ['dangerous', 'access any geographic locations', 'Allows an application to access any geographic locations persisted in the user\'s shared collection.'],
        'ACTIVITY_RECOGNITION': ['dangerous', 'allow application to recognize physical activity', 'Allows an application to recognize physical activity.'],
        'BIND_CALL_REDIRECTION_SERVICE': ['signature', '', 'Must be required by a CallRedirectionService, to ensure that only the system can bind to it.'],
        'BIND_CARRIER_MESSAGING_CLIENT_SERVICE': ['signature', '', 'A subclass of CarrierMessagingClientService must be protected with this permission.'],
        'CALL_COMPANION_APP': ['normal', '', 'Allows an app which implements the InCallService API to be eligible to be enabled as a calling companion app. This means that the Telecom framework will bind to the app\'s InCallService implementation when there are calls active. The app can use the InCallService API to view information about calls on the system and control these calls.'],
        'REQUEST_PASSWORD_COMPLEXITY': ['normal', '', 'Allows an application to request the screen lock complexity and prompt users to update the screen lock to a certain complexity level.'],
        'SMS_FINANCIAL_TRANSACTIONS': ['signature', 'Allows financial apps to read filtered sms messages', 'Allows financial apps to read filtered sms messages. Protection level: signature|appop'],
        'START_VIEW_PERMISSION_USAGE': ['signature', '', 'Allows the holder to start the permission usage screen for an app.'],
        'USE_FULL_SCREEN_INTENT': ['normal', '', 'Required for apps targeting Build.VERSION_CODES.Q that want to use notification full screen intents.'],
        'ACCESS_CALL_AUDIO': ['signature', 'Application can access call audio', 'Allows an application assigned to the Dialer role to be granted access to the telephony call audio streams, both TX and RX.'],
        'BIND_CONTROLS': ['signatureOrSystem', 'Allows SystemUI to request third party controls.', 'Allows SystemUI to request third party controls. Should only be requested by the System and required by ControlsProviderService declarations.'],
        'BIND_QUICK_ACCESS_WALLET_SERVICE': ['signature', '', 'Must be required by a QuickAccessWalletService to ensure that only the system can bind to it.'],
        'INTERACT_ACROSS_PROFILES': ['normal', '', 'Allows interaction across profiles in the same profile group.'],
        'LOADER_USAGE_STATS': ['signatureOrSystem', '', 'Allows a data loader to read a package\'s access logs. The access logs contain the set of pages referenced over time.'],
        'MANAGE_EXTERNAL_STORAGE': ['dangerous', 'Allows an application a broad access to external storage in scoped storage', 'Allows an application a broad access to external storage in scoped storage. Intended to be used by few apps that need to manage files on behalf of the users.'],
        'NFC_PREFERRED_PAYMENT_INFO': ['normal', '', 'Allows applications to receive NFC preferred payment service information.'],
        'QUERY_ALL_PACKAGES': ['normal', '', 'Allows query of any normal app on the device, regardless of manifest declarations.'],
        'READ_PRECISE_PHONE_STATE': ['dangerous', '', 'Allows read only access to precise phone state. Allows reading of detailed information about phone state for special-use applications such as dialers, carrier applications, or ims applications.'],
    },

    'MANIFEST_PERMISSION_GROUP':
        {
        'ACCOUNTS': 'Permissions for direct access to the accounts managed by the Account Manager.',
        'COST_MONEY': 'Used for permissions that can be used to make the user spend money without their direct involvement.',
        'DEVELOPMENT_TOOLS': 'Group of permissions that are related to development features.',
        'HARDWARE_CONTROLS': 'Used for permissions that provide direct access to the hardware on the device.',
        'LOCATION': 'Used for permissions that allow access to the user\'s current location.',
        'MESSAGES': 'Used for permissions that allow an application to send messages on behalf of the user or intercept messages being received by the user.',
        'NETWORK': 'Used for permissions that provide access to networking services.',
        'PERSONAL_INFO': 'Used for permissions that provide access to the user\'s private data, such as contacts, calendar events, e-mail messages, etc.',
        'PHONE_CALLS': 'Used for permissions that are associated with accessing and modifyign telephony state: intercepting outgoing calls, reading and modifying the phone state.',
        'STORAGE': 'Group of permissions that are related to SD card access.',
        'SYSTEM_TOOLS': 'Group of permissions that are related to system APIs.',
    },
}
