//
//  AppDelegate.m
//  ARPX
//
//  Created by cirrus on 8/13/12.
//  Copyright (c) 2012 cirrus. All rights reserved.
//

#import "AppDelegate.h"
#import "VendorViewData.h"
#import <ServiceManagement/ServiceManagement.h>
#import <Security/Authorization.h>
#import <SystemConfiguration/SystemConfiguration.h>

@interface AppDelegate ()
- (BOOL)blessHelperWithLabel:(NSString *)label error:(NSError **)error;
@end

@implementation AppDelegate

- (void)dealloc
{
    [lock dealloc];
    [statusImage dealloc];
    [statusHighlightImage dealloc];
    [super dealloc];
}

/*
- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    // Insert code here to initialize your application
}
*/

- (void) awakeFromNib {
    lock = [[NSLock alloc] init];
    enabled = false;
    sniffing = FALSE;
    rls = NULL;
    
    //Setup the notification center
    center = [NSUserNotificationCenter defaultUserNotificationCenter];
    [center setDelegate:self];
    
    //Check if helper tool is installed and the helper and gui CFBundleVersion matches
    NSDictionary* installedHelperJobData = (NSDictionary*)SMJobCopyDictionary(kSMDomainSystemLaunchd, (CFStringRef)@"org.cirrus.arpsniffer" );
    NSString* installedPath = [[installedHelperJobData objectForKey:@"ProgramArguments"] objectAtIndex:0];
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if(installedPath) {
        NSURL* installedPathURL = [NSURL fileURLWithPath:installedPath];
        NSDictionary* installedInfoPlist = (NSDictionary*)CFBundleCopyInfoDictionaryForURL((CFURLRef)installedPathURL);
        NSString* installedBundleVersion = [installedInfoPlist objectForKey:@"CFBundleVersion"];
        NSString* guiBundleVersion = [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleVersion"];
        if([fileManager fileExistsAtPath:installedPath] && [guiBundleVersion isEqual:installedBundleVersion]) {
            NSLog(@"Helper is installed.");
        } else {
            //Install the helper tool
            NSError *error = nil;
            if (![self blessHelperWithLabel:@"org.cirrus.arpsniffer" error:&error]) {
                NSLog(@"%@",[NSString stringWithFormat:@"Failed to bless helper. Error: %@", error]);
                exit(1);
            }
        }
    } else {
        //Install the helper tool
        NSError *error = nil;
        if (![self blessHelperWithLabel:@"org.cirrus.arpsniffer" error:&error]) {
            NSLog(@"%@",[NSString stringWithFormat:@"Failed to bless helper. Error: %@", error]);
            exit(1);
        }
    }

    [installedHelperJobData release];
   
    //Initialize the xpc
    connection = xpc_connection_create_mach_service("org.cirrus.arpsniffer", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    if (!connection) {
        NSLog(@"%@",@"Failed to create XPC connection.");
        return;
    }
    
    //Handle xpc data
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        [lock lock];
        xpc_type_t type = xpc_get_type(event);
        if (type == XPC_TYPE_ERROR) {
            if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
                NSLog(@"%@",@"XPC connection interupted.");
            } else if (event == XPC_ERROR_CONNECTION_INVALID) {
                NSLog(@"%@",@"XPC connection invalid, releasing.");
                xpc_release(connection);
            } else {
                NSLog(@"%@",@"Unexpected XPC connection error.");
            }
        } else {
            //The helper send some arp data
            const char *incoming = xpc_dictionary_get_string(event, "arpdata");
            NSString *data = [NSString stringWithUTF8String:incoming];
            NSArray *dataArray = [data componentsSeparatedByString:@"-"];
            NSString *SourceIP = [dataArray objectAtIndex:0];
            NSString *SourceMac = [dataArray objectAtIndex:1];
            NSDictionary *args = [NSDictionary dictionaryWithObjectsAndKeys:
                                      SourceIP, @"IP",
                                      SourceMac, @"MAC"
                                      , nil];
            //NSLog(@"ARP Data received: %@",args);
            //ARPList class should process them on the background
            [arpdata performSelectorInBackground:@selector(handleIP:) withObject:args];            
        }
        [lock unlock];  
    });
    xpc_connection_resume(connection);
    
    //Send a hello message
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    const char* request = "Hi there, helper service.";
    xpc_dictionary_set_string(message, "request", request);
    NSLog(@"%@",[NSString stringWithFormat:@"Sending request: %s", request]);
    xpc_connection_send_message_with_reply(connection, message, dispatch_get_main_queue(), ^(xpc_object_t event) {
        const char* response = xpc_dictionary_get_string(event, "reply");
        NSLog(@"%@",[NSString stringWithFormat:@"Received response: %s.", response]);
    });
    
    //Initialize the status bar
    statusItem = [[[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength] retain];
    NSBundle *bundle =[NSBundle mainBundle];
    statusImage = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"fireblack" ofType:@"png"]];
    statusHighlightImage = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"fireblue" ofType:@"png"]];
    [statusItem setImage:statusImage];
    [statusItem setAlternateImage:statusHighlightImage];
    [statusItem setMenu:statusMenu];
    [statusItem setToolTip:@"ARPX"];
    [statusItem setHighlightMode:YES];
    
    //Load the vendor plist
    vendorData = [[VendorViewData alloc] init];
    vendorTableView.dataSource = vendorData;
    
    //Load the saved arp entries if found
    NSDictionary *loadedArp = [[NSUserDefaults standardUserDefaults] objectForKey:@"ARPData"];
    if([loadedArp count]>0) {
        arpdata = [[ARPList alloc] initWithDictionary:loadedArp initWithVendorData:vendorData withArpTable:arpTableView withNotification:center];
    } else {
        arpdata = [[ARPList alloc] initWithVendorData:vendorData withArpTable:arpTableView withNotification:center];
    }
    arpTableView.dataSource = arpdata;
    //[arpTableView setAllowsMultipleSelection:YES];
    //Load the preferences to automatically start or not
    enabled = [[NSUserDefaults standardUserDefaults] boolForKey:@"enabled"];
    NSLog(@"Starting automatically: %@",enabled?@"YES":@"NO");
    //Set the image and menuitem according to the enabled status
    if(!enabled) {
        //Monitoring is disabled
        [enableDisableItem setTitle:@"Enable"];
        NSLog(@"Monitoring was disabled.");
        NSImage *black = [[NSImage alloc] initWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"fireblack" ofType:@"png"]];
        [statusItem setImage:black];
        [black release];
    } else {
        //Monitoring is enabled
        [enableDisableItem setTitle:@"Disable"];
        NSLog(@"Monitoring was enabled.");
        NSImage *red = [[NSImage alloc] initWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"firered" ofType:@"png"]];
        [statusItem setImage:red];
        [red release];
        [self startNetworkMonitor];
    }
    NSTimer *t = [[NSTimer scheduledTimerWithTimeInterval:50 target:self selector:@selector(savePreferences) userInfo:nil repeats:YES] retain];
    [t autorelease];
}

- (BOOL)blessHelperWithLabel:(NSString *)label error:(NSError **)error {
	BOOL result = NO;
	AuthorizationItem authItem		= { kSMRightBlessPrivilegedHelper, 0, NULL, 0 };
	AuthorizationRights authRights	= { 1, &authItem };
	AuthorizationFlags flags		=	kAuthorizationFlagDefaults				|
    kAuthorizationFlagInteractionAllowed	|
    kAuthorizationFlagPreAuthorize			|
    kAuthorizationFlagExtendRights;
	AuthorizationRef authRef = NULL;
	/* Obtain the right to install privileged helper tools (kSMRightBlessPrivilegedHelper). */
	OSStatus status = AuthorizationCreate(&authRights, kAuthorizationEmptyEnvironment, flags, &authRef);
	if (status != errAuthorizationSuccess) {
        NSLog(@"%@",[NSString stringWithFormat:@"Failed to create AuthorizationRef. Error code: %d", status]);
        
	} else {
		/* This does all the work of verifying the helper tool against the application
		 * and vice-versa. Once verification has passed, the embedded launchd.plist
		 * is extracted and placed in /Library/LaunchDaemons and then loaded. The
		 * executable is placed in /Library/PrivilegedHelperTools.
		 */
		result = SMJobBless(kSMDomainSystemLaunchd, (CFStringRef)label, authRef, (CFErrorRef *)error);
	}
	return result;
}

- (IBAction)enableDisable:(id)sender {
    if(enabled) {
        if(sniffing) {
            [self stopSniffing];
        }
        //Monitoring will be disabled
        [self stopNetworkMonitor];
        [enableDisableItem setTitle:@"Enable"];
        NSLog(@"Monitoring was disabled.");
        NSImage *black = [[NSImage alloc] initWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"fireblack" ofType:@"png"]];
        [statusItem setImage:black];
        [black release];
    } else {
        if(sniffing) {
            [self stopSniffing];
        }
        //Monitoring will be enabled
        [self startNetworkMonitor];
        [enableDisableItem setTitle:@"Disable"];
        NSLog(@"Monitoring was enabled.");
        NSImage *red = [[NSImage alloc] initWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"firered" ofType:@"png"]];
        [statusItem setImage:red];
        [red release];
    }
}

- (void) startSniffing: (NSString*)interface {
    if([interface isEqualToString:@""] || !interface) {
        NSLog(@"Requested to start sniffing, but not interface was provided");
        return;
    }
    if(sniffing) {
        NSLog(@"startSniffing was called, but we are already sniffing.");
        //[self stopSniffing];
    }
    if(!sniffing) {
        watchDog = [[NSTimer scheduledTimerWithTimeInterval:10 target:self selector:@selector(sniffingWatchdog) userInfo:nil repeats:YES] retain];
        [watchDog autorelease];
        xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
        const char* device = [interface cStringUsingEncoding:NSASCIIStringEncoding];
        xpc_dictionary_set_string(message, "start", device);
        NSLog(@"Request for sniffing on interface %@",interface);
        xpc_connection_send_message_with_reply(connection, message, dispatch_get_main_queue(), ^(xpc_object_t event) {
            const char* response = xpc_dictionary_get_string(event, "reply");
            NSLog(@"%@",[NSString stringWithFormat:@"Received response: %s.", response]);
            if(strncmp(response,"START_OK",strlen(response))==0) {
                NSImage *red = [[NSImage alloc] initWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"firered" ofType:@"png"]];
                [statusItem setImage:red];
                [red release];
                sniffing = TRUE;
                NSLog(@"Sniffing was started");
            } else {
                NSLog(@"Sniffing was not started");
            }
        });
    }
}

- (void) stopSniffing {
    if(sniffing) {
        xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(message, "stop", "stop");
        xpc_connection_send_message_with_reply(connection, message, dispatch_get_main_queue(), ^(xpc_object_t event) {
            const char* response = xpc_dictionary_get_string(event, "reply");
            NSLog(@"%@",[NSString stringWithFormat:@"Received response: %s.", response]);
            if(strncmp(response,"STOP_OK",strlen(response))==0) {
                NSImage *black = [[NSImage alloc] initWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"fireblack" ofType:@"png"]];
                [statusItem setImage:black];
                [black release];
                sniffing = FALSE;
                NSLog(@"Sniffing was stopped");
                [watchDog invalidate];
                watchDog = nil;
            } else {
                NSLog(@"Sniffing was not stopped");
            }
        });
    } else {
        NSLog(@"stopSniffing was called, but we are not sniffing.");
    }
}

static void networkChange(SCDynamicStoreRef store, CFArrayRef changedKeys, void *context) {
    AppDelegate *self = context;
    NSLog(@"Network change received...");
    CFPropertyListRef newState = NULL;
    newState = SCDynamicStoreCopyValue(store, CFArrayGetValueAtIndex(changedKeys, 0));
    if(newState==NULL) {
        NSLog(@"No primary interface was identified. Stop sniffing.");
        [self stopSniffing];
    } else {
        CFStringRef InterfaceName = CFDictionaryGetValue((CFDictionaryRef)newState, @"PrimaryInterface");
        NSLog(@"Primary Interface is now: %@",InterfaceName);
        [self startSniffing:(NSString*)InterfaceName];
        CFRelease(newState);
    }
}

- (NSString*) getPrimaryInterface {
    SCDynamicStoreRef storeRef = SCDynamicStoreCreate(NULL, (CFStringRef)@"FindCurrentInterfaceIpMac", NULL, NULL);
    CFPropertyListRef global = SCDynamicStoreCopyValue (storeRef,CFSTR("State:/Network/Global/IPv4"));
    if(global==NULL) {
        NSLog(@"No primary interface");
        return NULL;
    } else {
        CFStringRef InterfaceName = CFDictionaryGetValue((CFDictionaryRef)global, @"PrimaryInterface");
        NSString *interface = [NSString stringWithString:(NSString*)InterfaceName];
        CFRelease(global);
        NSLog(@"Primary Interface is: %@",(NSString *)interface);
        return interface;
    }
}

- (void) startNetworkMonitor {
    //Start sniffing on primary interface
    [self startSniffing:[self getPrimaryInterface]];
    //Monitoring for network changes
    if(rls==NULL) {
        SCDynamicStoreRef store = NULL;
        SCDynamicStoreContext context = {0, self, NULL, NULL, NULL};
        store = SCDynamicStoreCreate(NULL,CFSTR("global-network-watcher"), networkChange, &context);
        if (store == NULL) {
            NSLog(@"SCDynamicStoreCreate() failed");
        }
        NSLog(@"Store Created");
        if(SCDynamicStoreSetNotificationKeys(store,NULL,(CFArrayRef)[NSArray arrayWithObjects:@"State:/Network/Global/IPv4", nil])) {
            NSLog(@"SCDynamicStoreSetNotificationKeys() ok");
        }
        rls = SCDynamicStoreCreateRunLoopSource(NULL,store,0);
        CFRunLoopAddSource(CFRunLoopGetCurrent(),rls,kCFRunLoopCommonModes);
        NSLog(@"Started monitoring...");
        enabled = TRUE;
    } else {
        NSLog(@"rls in not NULL. Probably already monitoring");
    }
}

- (void) stopNetworkMonitor {
    enabled = FALSE;
    if(rls!=NULL) {
        CFRunLoopSourceInvalidate(rls);
        CFRelease(rls);
        rls = NULL;
    }
    NSLog(@"Stopped monitoring...");
}

//show/hide the vendor panel
- (IBAction)showVendorPanel:(id)sender {
    if ( [vendorPanel isVisible]) {
        [vendorPanel orderOut:self];
    } else {
        [vendorPanel makeKeyAndOrderFront:self];
    }
}

//show/hide the arp panel
- (IBAction)showArpPanel:(id)sender {
    [arpTableView reloadData];
    if ( [arpPanel isVisible]) {
        [arpPanel orderOut:self];
    } else {
        [arpPanel makeKeyAndOrderFront:self];
        [arpPanel makeKeyWindow];
        [arpPanel becomeKeyWindow];
        [arpPanel becomeMainWindow];
    }
}

- (void) savePreferences {
    [lock lock];
    NSLog(@"Saving settings to file...");
    [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:@"enabled"];
    [[NSUserDefaults standardUserDefaults] setObject:[arpdata getArp] forKey:@"ARPData"];
    NSLog(@"Saved %lu entries",[[arpdata getArp] count]);
    [lock unlock];
}

- (void) sniffingWatchdog {
    NSLog(@"Requesting status update");
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "status", "status");
    xpc_connection_send_message_with_reply(connection, message, dispatch_get_main_queue(), ^(xpc_object_t event) {
        const char* response = xpc_dictionary_get_string(event, "status_reply");
        NSLog(@"%@",[NSString stringWithFormat:@"Received response: %s.", response]);
        if(strncmp(response,"NO",strlen(response))==0) {
            sniffing = FALSE;
            [self stopNetworkMonitor];
            [enableDisableItem setTitle:@"Enable"];
            NSLog(@"Monitoring was disabled.");
            NSImage *black = [[NSImage alloc] initWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"fireblack" ofType:@"png"]];
            [statusItem setImage:black];
            [black release];
            [watchDog invalidate];
            watchDog = nil;
            CFStringRef title = (CFStringRef)@"ARPX Error";
            CFStringRef informativeText = (CFStringRef)@"The watchdog detected that sniffing has been stopped";
            CFOptionFlags options = kCFUserNotificationNoteAlertLevel;
            CFOptionFlags responseFlags = 0;
            CFUserNotificationDisplayAlert(0, options, NULL, NULL, NULL,
                                           title,
                                           informativeText, NULL,
                                           NULL,NULL, &responseFlags);
        }
    });
}

//quit the application
- (IBAction)quit:(id)sender {
    NSLog(@"Quit was called");
    //Save the preferences to the user preferences
    [self savePreferences];
    //Message the helper to stop
    NSLog(@"Sending kill event to helper");
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "kill", "kill");
    xpc_connection_send_message(connection, message);
    xpc_release(message);
    
    [NSApp terminate:self];
}

- (void)handleQuitEvent:(NSAppleEventDescriptor*)event withReplyEvent:(NSAppleEventDescriptor*)replyEvent {
    //Save the preferences to the user preferences
    [self savePreferences];
    
    //Message the helper to stop
    NSLog(@"Sending kill event to helper");
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "kill", "kill");
    xpc_connection_send_message(connection, message);
    xpc_release(message);
}

- (void) userNotificationCenter: (NSUserNotificationCenter *) incenter didActivateNotification: (NSUserNotification *) notification
{
    CFStringRef title = (CFStringRef)notification.title;
    CFStringRef informativeText = (CFStringRef)notification.informativeText;
    [incenter removeDeliveredNotification:notification];
    CFOptionFlags options = kCFUserNotificationNoteAlertLevel;
    CFOptionFlags responseFlags = 0;
    CFUserNotificationDisplayAlert(0, options, NULL, NULL, NULL,
                                   title,
                                   informativeText, NULL,
                                   NULL,NULL, &responseFlags);
}
@end
