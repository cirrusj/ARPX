//
//  ARPList.h
//  arpmonitor
//
//  Created by cirrus on 8/14/12.
//  Copyright (c) 2012 cirrus. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VendorViewData.h"

@interface ARPList : NSObject <NSTableViewDataSource> {
    NSMutableDictionary *arpListing;
    VendorViewData *vendorData;
    NSLock *lock;
    NSTableView *arpTableView;
    NSUserNotificationCenter *center;
}

- (id) init;
- (id) initWithVendorData: (VendorViewData*)invendorData withArpTable:(NSTableView*)arpTableView withNotification:(NSUserNotificationCenter*)incenter;
- (id) initWithDictionary: (NSDictionary*)inarpdata initWithVendorData: (VendorViewData*)invendorData withArpTable:(NSTableView*)inarpTableView withNotification:(NSUserNotificationCenter*)incenter;

- (BOOL) IPinList: (NSString*)IP;
- (BOOL) addIP: (NSString*)IP withMAC: (NSString*)mac withHostName: (NSString*)hostname;
- (BOOL) addIP: (NSString*)IP withMAC: (NSString*)mac;
- (BOOL) addIP: (NSString*)IP withDetails: (NSMutableDictionary*)details;
- (BOOL) updateIP: (NSString*)IP withNewMAC: (NSString*)mac;
- (BOOL) updateIP: (NSString*)IP withNewMAC: (NSString*)mac withNewHostName: (NSString*)hostname;
- (BOOL) updateIP: (NSString*)IP withNewHostName: (NSString*)hostname;
- (BOOL) updateLastSeenOnIP:(NSString*)IP;
- (void) removeIP: (NSString*)IP;
- (NSString*) print;
- (BOOL)isValidIPAddress: (NSString*)IP;
- (BOOL) checkIP: (NSString*)IP withMAC: (NSString*)mac;
- (NSUInteger) count;
- (void) handleIP: (NSDictionary*)args;
- (BOOL) writeToFile: (NSString*)fileName;
- (id) getArp;

- (NSInteger)numberOfRowsInTableView:(NSTableView *)aTableView;
- (id)tableView:(NSTableView *)aTableView objectValueForTableColumn:(NSTableColumn *)aTableColumn row:(NSInteger)rowIndex;

@end
