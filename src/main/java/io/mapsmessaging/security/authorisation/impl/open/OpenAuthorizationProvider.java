package io.mapsmessaging.security.authorisation.impl.open;

import io.mapsmessaging.configuration.ConfigurationProperties;
import io.mapsmessaging.security.access.Group;
import io.mapsmessaging.security.access.Identity;
import io.mapsmessaging.security.authorisation.*;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

public class OpenAuthorizationProvider implements AuthorizationProvider {

  @Override
  public String getName() {
    return "Open";
  }

  @Override
  public   AuthorizationProvider create(ConfigurationProperties config, Permission[]  permissions){
    return this;
  }

  @Override
  public boolean canAccess(Identity identity, Permission permission, ProtectedResource protectedResource) {
    return true;
  }

  @Override
  public void grantAccess(Grantee grantee, Permission permission, ProtectedResource protectedResource) {
    //Nothing to do, this is open
  }

  @Override
  public void revokeAccess(Grantee grantee, Permission permission, ProtectedResource protectedResource) {
    //Nothing to do, this is open
  }

  @Override
  public void registerIdentity(UUID identityId) {
    //Nothing to do, this is open
  }

  @Override
  public void deleteIdentity(UUID identityId) {
    //Nothing to do, this is open
  }

  @Override
  public void registerGroup(UUID groupId) {
    //Nothing to do, this is open
  }

  @Override
  public void deleteGroup(UUID groupId) {
    //Nothing to do, this is open
  }

  @Override
  public void addGroupMember(UUID groupId, UUID identityId) {
    //Nothing to do, this is open
  }

  @Override
  public void removeGroupMember(UUID groupId, UUID identityId) {
    //Nothing to do, this is open
  }

  @Override
  public void registerResource(ProtectedResource protectedResource, ResourceCreationContext resourceCreationContext) {
    //Nothing to do, this is open
  }

  @Override
  public void deleteResource(ProtectedResource protectedResource) {
    //Nothing to do, this is open
  }

  @Override
  public Collection<Grant> getGrantsForIdentity(Identity identity) {
    return List.of();
  }

  @Override
  public Collection<Grant> getGrantsForGroup(Group group) {
    return List.of();
  }

  @Override
  public Collection<Grant> getGrantsForResource(ProtectedResource protectedResource) {
    return List.of();
  }
}
