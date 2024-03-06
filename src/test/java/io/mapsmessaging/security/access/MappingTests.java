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
import io.mapsmessaging.security.access.mapping.GroupMapManagement;
import io.mapsmessaging.security.access.mapping.UserIdMap;
import io.mapsmessaging.security.access.mapping.UserMapManagement;
import io.mapsmessaging.security.access.mapping.store.MapFileStore;
import io.mapsmessaging.security.access.mapping.store.MapStore;
import java.util.Comparator;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class MappingTests extends BaseSecurityTest {

  @Test
  void loadingAndSavingTest() {
    MapStore<UserIdMap> userStore = new MapFileStore<>("userTest.map");
    MapStore<GroupIdMap> groupStore = new MapFileStore<>("groupTest.map");

    UserMapManagement userMapManagement = new UserMapManagement(userStore);
    GroupMapManagement groupMapManagement = new GroupMapManagement(groupStore);

    generateGroupEntries(1000, groupMapManagement);
    generateUserEntries(1000, userMapManagement, groupMapManagement);

    userMapManagement.save();
    groupMapManagement.save();

    UserMapManagement userMapManagement1 = new UserMapManagement(userStore);
    GroupMapManagement groupMapManagement1 = new GroupMapManagement(groupStore);

    Assertions.assertEquals(userMapManagement1.size(), userMapManagement.size());
    List<UserIdMap> userIdMapList = userMapManagement.getAll();
    List<UserIdMap> userIdMapList1 = userMapManagement1.getAll();
    userIdMapList.sort(new UserIdMapComparator());
    userIdMapList1.sort(new UserIdMapComparator());
    for (int i = 0; i < userIdMapList.size(); i++) {
      Assertions.assertEquals(userIdMapList.get(i), userIdMapList1.get(i));
    }

    Assertions.assertEquals(groupMapManagement.size(), groupMapManagement1.size());
    List<GroupIdMap> groupIdMapList = groupMapManagement.getAll();
    List<GroupIdMap> groupIdMapList1 = groupMapManagement1.getAll();
    groupIdMapList.sort(new GroupIdMapComparator());
    groupIdMapList1.sort(new GroupIdMapComparator());

    for (int i = 0; i < groupIdMapList.size(); i++) {
      Assertions.assertEquals(groupIdMapList.get(i), groupIdMapList1.get(i));
    }
  }

  public static class UserIdMapComparator implements Comparator<UserIdMap> {
    @Override
    public int compare(UserIdMap o1, UserIdMap o2) {
      return o1.getAuthId().compareTo(o2.getAuthId());
    }
  }

  public static class GroupIdMapComparator implements Comparator<GroupIdMap> {
    @Override
    public int compare(GroupIdMap o1, GroupIdMap o2) {
      return o1.getAuthId().compareTo(o2.getAuthId());
    }
  }
}
