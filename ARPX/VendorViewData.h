//
//  VendorViewData.h
//  ARPX
//
//  Created by cirrus on 8/30/12.
//  Copyright (c) 2012 cirrus. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface VendorViewData : NSObject <NSTableViewDataSource> {
    NSMutableDictionary *vendorData;
}

- (id)init;

- (NSInteger)numberOfRowsInTableView:(NSTableView *)aTableView;

- (id)tableView:(NSTableView *)aTableView objectValueForTableColumn:(NSTableColumn *)aTableColumn row:(NSInteger)rowIndex;

- (NSString*) vendorForMac: (NSString*) mac;

@end
