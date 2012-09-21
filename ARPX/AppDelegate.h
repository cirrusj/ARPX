//
//  AppDelegate.h
//  ARPX
//
//  Created by cirrus on 8/13/12.
//  Copyright (c) 2012 cirrus. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "VendorViewData.h"
#import "ARPList.h"
#import "NSNewTableView.h"

@interface AppDelegate : NSObject <NSApplicationDelegate, NSMenuDelegate, NSUserNotificationCenterDelegate> {
    IBOutlet NSMenu *statusMenu;
    IBOutlet NSPanel *vendorPanel;
    IBOutlet NSPanel *arpPanel;
    IBOutlet NSTableView *vendorTableView;
    IBOutlet NSNewTableView *arpTableView;
    IBOutlet NSMenuItem *enableDisableItem;
    NSStatusItem * statusItem;
    NSImage *statusImage;
    NSImage *statusHighlightImage;
    VendorViewData *vendorData;
    ARPList *arpdata;
    xpc_connection_t connection;
    NSLock *lock;
    BOOL sniffing;
    BOOL enabled;
    CFRunLoopSourceRef rls;
    NSUserNotificationCenter *center;
    NSTimer *watchDog;
}

- (IBAction)enableDisable:(id)sender;
- (IBAction)showVendorPanel:(id)sender;
- (IBAction)showArpPanel:(id)sender;

- (void) startSniffing: (NSString*)interface;
- (void) stopSniffing;

@property (assign) IBOutlet NSWindow *window;

@end
