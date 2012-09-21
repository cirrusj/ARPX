//
//  ARPList.m
//  arpmonitor
//
//  Created by cirrus on 8/14/12.
//  Copyright (c) 2012 cirrus. All rights reserved.
//

#import "ARPList.h"
#include <arpa/inet.h>

@implementation ARPList

- (id) getArp {
    return arpListing;
}

- (id) init {
    self = [super init];
    if (self) {
        arpListing = [NSMutableDictionary dictionary];
        [arpListing retain];
        lock = [[NSLock alloc] init];
    }
    return self;
}

- (id) initWithVendorData: (VendorViewData*)invendorData withArpTable:(NSTableView*)inarpTableView withNotification:(NSUserNotificationCenter*)incenter {
    self = [super init];
    if (self) {
        arpListing = [NSMutableDictionary dictionary];
        vendorData = invendorData;
        arpTableView = inarpTableView;
        center = incenter;
        [arpListing retain];
        lock = [[NSLock alloc] init];
    }
    return self;
}

- (id) initWithDictionary: (NSDictionary*)inarpdata initWithVendorData: (VendorViewData*)invendorData withArpTable:(NSTableView*)inarpTableView withNotification:(NSUserNotificationCenter*)incenter{
    self = [super init];
    if (self) {
        arpListing = [NSMutableDictionary dictionaryWithDictionary:inarpdata];
        vendorData = invendorData;
        arpTableView = inarpTableView;
        center = incenter;
        [arpListing retain];
        lock = [[NSLock alloc] init];
    }
    return self;
}


- (BOOL) loadFromFile: (NSString*)fileName {
    NSLog(@"Loading ARP data from file %@",fileName);
    arpListing = [NSMutableDictionary dictionaryWithContentsOfFile:fileName];
    return YES;
}

- (NSString*) print {
    NSString *result =[NSString stringWithFormat:@"%@",arpListing];
    return result;
}

- (BOOL) IPinList: (NSString*)IP {
    id obj = [arpListing objectForKey:IP];
    if(obj) {
        return YES;
    } else {
        return NO;
    }
}
- (BOOL) addIP: (NSString*)IP withMAC: (NSString*)mac withHostName: (NSString*)hostname {
    NSMutableDictionary *details = [NSMutableDictionary dictionaryWithObjectsAndKeys:mac,@"MAC",hostname,@"NAME", nil];
    return [self addIP:IP withDetails:details];
}
- (BOOL) addIP: (NSString*)IP withMAC: (NSString*)mac {
    NSMutableDictionary *details = [NSMutableDictionary dictionaryWithObjectsAndKeys:mac,@"MAC",nil];
    return [self addIP:IP withDetails:details];
}
- (BOOL) addIP: (NSString*)IP withDetails: (NSMutableDictionary*)details {
//    [lock lock];
    if([self isValidIPAddress:IP]) {
        if(![[details allKeys] containsObject:@"LASTSEEN"]) {
            [details setObject:[NSDate date] forKey:@"LASTSEEN"];
        }
        [arpListing setObject:details forKey:IP];
//        [lock unlock];
        return YES;
    } else {
        NSLog(@"Invalid IP (%@) was given. Ignoring.",IP);
//        [lock unlock];
        return NO;
    }
}

- (BOOL) updateIP: (NSString*)IP withNewMAC: (NSString*)mac {
//    [lock lock];
    if([self IPinList:IP]) {
        id obj = [arpListing objectForKey:IP];
        [obj setObject:mac forKey:@"MAC"];
        [obj setObject:[NSDate date] forKey:@"LASTSEEN"];
//        [lock unlock];
        return YES;
    } else {
        NSLog(@"IP (%@) was not in the list.",IP);
//        [lock unlock];
        return NO;
    }
}

- (BOOL) updateLastSeenOnIP:(NSString*)IP {
//    [lock lock];
    if([self IPinList:IP]) {
        id obj = [arpListing objectForKey:IP];
        [obj setObject:[NSDate date] forKey:@"LASTSEEN"];
//        [lock unlock];
        return YES;
    } else {
        NSLog(@"IP (%@) was not in the list.",IP);
//        [lock unlock];
        return NO;
    }
}
- (BOOL) updateIP: (NSString*)IP withNewMAC: (NSString*)mac withNewHostName: (NSString*)hostname {
//    [lock lock];
    if([self IPinList:IP]) {
        id obj = [arpListing objectForKey:IP];
        [obj setObject:mac forKey:@"MAC"];
        [obj setObject:hostname forKey:@"NAME"];
        [obj setObject:[NSDate date] forKey:@"LASTSEEN"];
//        [lock unlock];
        return YES;
    } else {
        NSLog(@"IP (%@) was not in the list.",IP);
//        [lock unlock];
        return NO;
    }
}

- (BOOL) updateIP: (NSString*)IP withNewHostName: (NSString*)hostname {
//    [lock lock];
    if([self IPinList:IP]) {
        id obj = [arpListing objectForKey:IP];
        [obj setObject:hostname forKey:@"NAME"];
//        [lock unlock];
        return YES;
    } else {
        NSLog(@"IP (%@) was not in the list.",IP);
//        [lock unlock];
        return NO;
    }
}

- (BOOL) checkIP: (NSString*)IP withMAC: (NSString*)mac {
    NSString *oldmac = [[arpListing objectForKey:IP] objectForKey:@"MAC"];
    //NSLog(@"Old MAC: %@, New MAC: %@", oldmac,mac);
    if([mac isEqualToString:oldmac]) {
        //NSLog(@"checkIP will return YES");
        return YES;
    } else {
        //NSLog(@"checkIP will return NO");
        return NO;
    }
}

- (void) removeIP: (NSString*)IP {
    [lock lock];
    [arpListing removeObjectForKey:IP];
    [lock unlock];
}

- (void) handleIP: (NSDictionary*)args {
    [lock lock];
    NSString *IP = [args objectForKey:@"IP"];
    NSString *mac = [args objectForKey:@"MAC"];
    NSString *vendor = [vendorData vendorForMac:mac];
    NSString *hostname = NULL;
    if([self IPinList:IP]) {
        //IP in list. Check it.
        if([self checkIP:IP withMAC:mac]) {
            //the same no problem
            //NSLog(@"Already in database. Updating timestamp");
            [self updateLastSeenOnIP:IP];
        } else {
            //mac changed. possible arp spoofing?
            NSString *oldmac = [[arpListing objectForKey:IP] objectForKey:@"MAC" ];
            NSString *oldvendor = [vendorData vendorForMac:oldmac];
            NSString *hostname = [[arpListing objectForKey:IP] objectForKey:@"NAME" ];
            NSMutableString *notification = [NSMutableString stringWithFormat:@"MAC address for IP: %@ ",IP];
            if(hostname) {
                [notification appendFormat:@"(%@) ",hostname];
            }
            [notification appendFormat:@"was changed from MAC: %@ ",oldmac];
            if(oldvendor) {
                [notification appendFormat:@"(%@) ",oldvendor];
            }
            [notification appendFormat:@"to MAC: %@ ",mac];
            if(vendor) {
                [notification appendFormat:@"(%@) ",vendor];
            }
            NSLog(@"Alert: %@", notification);
            [self notificationWithText:notification withTitle:@"MAC Address changed"];
            [self updateIP:IP withNewMAC:mac];
        }
    } else {
        //IP not in list add it.
        hostname = [[NSHost hostWithAddress:IP] name];
        //Adding IP to list
        NSLog(@"Add IP (%@) to list.",IP);
        if(hostname) {
            [self addIP:IP withMAC:mac withHostName:hostname];
        } else {
            [self addIP:IP withMAC:mac];
        }
        NSMutableString *notification = [NSMutableString stringWithFormat:@"IP: %@ ",IP];
        if(hostname) {
            [notification appendFormat:@"(%@) ",hostname];
        }
        [notification appendFormat:@"\nMAC: %@ ",mac];
        if(vendor) {
            [notification appendFormat:@"(%@)",vendor];
        }
        [self notificationWithText:notification withTitle:@"New station"];
        NSLog(@"New station %@", notification);
    }
    [arpTableView reloadData];
    [lock unlock];
}

- (BOOL)isValidIPAddress: (NSString*)IP
{
    if(IP) {
        const char *utf8 = [IP UTF8String];
        int success;
        
        struct in_addr dst;
        success = inet_pton(AF_INET, utf8, &dst);
        if (success != 1) {
            struct in6_addr dst6;
            success = inet_pton(AF_INET6, utf8, &dst6);
        }
        return (success == 1 ? TRUE : FALSE);
    } else {
        NSLog(@"Blank IP in isValidIPAddress");
        return FALSE;
    }
}

- (BOOL) writeToFile: (NSString*)fileName {
    NSLog(@"Writing ARP data to file %@",fileName);
    return [arpListing writeToFile:fileName atomically:NO];
}

- (NSUInteger) count {
    if(arpListing) {
        return [arpListing count];
    } else {
        return 0;
    }
}

#pragma mark NSTableView related
- (NSInteger)numberOfRowsInTableView:(NSTableView *)aTableView {
    NSUInteger count = [[arpListing allKeys] count];
    return count;
}

- (id)tableView:(NSTableView *)aTableView objectValueForTableColumn:(NSTableColumn *)aTableColumn row:(NSInteger)rowIndex {
    NSString *columnIdentifer = [aTableColumn identifier];
    NSArray *keys = [arpListing allKeys];
    if ([columnIdentifer isEqual:@"IP"]) {
        return [keys objectAtIndex:rowIndex];
    } else if ([columnIdentifer isEqual:@"MAC"]) {
        return [[arpListing objectForKey:[keys objectAtIndex:rowIndex]] objectForKey:@"MAC"];
    } else if ([columnIdentifer isEqual:@"Name"]) {
        return [[arpListing objectForKey:[keys objectAtIndex:rowIndex]] objectForKey:@"NAME"];
    } else if ([columnIdentifer isEqual:@"Last"]) {
        NSDateFormatter *dateFormatter = [[[NSDateFormatter alloc] init] autorelease];
        [dateFormatter setDateFormat:@"HH:mm:ss dd-MM-yyyy"];
        [dateFormatter setLocale:[NSLocale currentLocale]];
        return [dateFormatter stringFromDate:[[arpListing objectForKey:[keys objectAtIndex:rowIndex]] objectForKey:@"LASTSEEN"]];
    }
    return NULL;
}

//TODO
- (void)tableView:(NSTableView *)aTableView sortDescriptorsDidChange:(NSArray *)oldDescriptors {
    [arpListing keysSortedByValueUsingComparator:^NSComparisonResult(id obj1, id obj2) {
        NSLog(@"1: %@ - 2: %@",obj1,obj2);
        return NSOrderedSame;
    }];
}

#pragma mark Notification Center Support
- (void) notificationWithText:(NSString*)text withTitle:(NSString*)title {
    NSUserNotification *notification = [[NSUserNotification alloc] init];
    [notification setTitle:title];
    [notification setInformativeText:text];
    [notification setDeliveryDate:[NSDate dateWithTimeInterval:1 sinceDate:[NSDate date]]];
    [notification setSoundName:NSUserNotificationDefaultSoundName];
//    [notification setHasActionButton:TRUE];
    [center scheduleNotification:notification];
    [notification release];
}
@end
