/*
 * Copyright [ 2020 - 2024 ] [Matthew Buckton]
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.mapsmessaging.security.access;

import io.mapsmessaging.security.access.mapping.GroupIdMap;
import io.mapsmessaging.security.access.mapping.GroupMapParser;
import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.UserMapParser;
import io.mapsmessaging.security.uuid.UuidGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.UUID;

public class UserAndGroupIdTest {

  @Test
  void testUserId(){
    UUID uuid = UuidGenerator.getInstance().generate();
    UserIdMap userIdMap = new UserIdMap(uuid, "aName", "anAuth");

    Assertions.assertEquals(uuid, userIdMap.getAuthId());
    Assertions.assertEquals("aName", userIdMap.getUsername());
    Assertions.assertEquals("anAuth", userIdMap.getAuthDomain());

    UserIdMap userIdMap1 = new UserIdMap(uuid, "aName", "anAuth");
    Assertions.assertEquals(userIdMap, userIdMap1);

    UserIdMap userIdMap2 = new UserIdMap(uuid, "aName", "anAuth1");
    Assertions.assertNotEquals(userIdMap, userIdMap2);

    UserIdMap userIdMap3 = new UserIdMap(uuid, "aName1", "anAuth");
    Assertions.assertNotEquals(userIdMap, userIdMap3);
    UserIdMap userIdMap4 = new UserIdMap(UuidGenerator.getInstance().generate(), "aName", "anAuth");
    Assertions.assertNotEquals(userIdMap, userIdMap4);
  }

  @Test
  void testGroupId(){
    UUID uuid = UuidGenerator.getInstance().generate();
    GroupIdMap groupIdMap = new GroupIdMap(uuid, "aName", "anAuth");

    Assertions.assertEquals(uuid, groupIdMap.getAuthId());
    Assertions.assertEquals("aName", groupIdMap.getGroupName());
    Assertions.assertEquals("anAuth", groupIdMap.getAuthDomain());

    GroupIdMap groupIdMap1 = new GroupIdMap(uuid, "aName", "anAuth");
    Assertions.assertEquals(groupIdMap, groupIdMap1);

    GroupIdMap groupIdMap2 = new GroupIdMap(uuid, "aName", "anAuth1");
    Assertions.assertNotEquals(groupIdMap, groupIdMap2);

    GroupIdMap groupIdMap3 = new GroupIdMap(uuid, "aName1", "anAuth");
    Assertions.assertNotEquals(groupIdMap, groupIdMap3);
    GroupIdMap groupIdMap4 = new GroupIdMap(UuidGenerator.getInstance().generate(), "aName", "anAuth");
    Assertions.assertNotEquals(groupIdMap, groupIdMap4);
  }

  @Test
  void testUserParsing(){
    UserMapParser parser = new UserMapParser();
    UUID uuid = UuidGenerator.getInstance().generate();
    UserIdMap userIdMap = parser.parse(uuid.toString()+" = authDomain:username");
    Assertions.assertEquals("authDomain", userIdMap.getAuthDomain());
    Assertions.assertEquals("username", userIdMap.getUsername());
    Assertions.assertEquals(uuid, userIdMap.getAuthId());
  }

  @Test
  void testGroupParsing(){
    GroupMapParser parser = new GroupMapParser();
    UUID uuid = UuidGenerator.getInstance().generate();
    GroupIdMap groupIdMap = parser.parse(uuid.toString()+" = authDomain:groupname");
    Assertions.assertEquals("authDomain", groupIdMap.getAuthDomain());
    Assertions.assertEquals("groupname", groupIdMap.getGroupName());
    Assertions.assertEquals(uuid, groupIdMap.getAuthId());
  }
}
