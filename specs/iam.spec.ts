import {
  IAMClient,
  GetPolicyCommand,
  GetPolicyVersionCommand,
  GetRoleCommand,
  ListAttachedRolePoliciesCommand,
  GetGroupCommand,
  ListAttachedGroupPoliciesCommand,
  GetUserCommand,
  ListGroupsForUserCommand
} from '@aws-sdk/client-iam';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';

// Initialize the IAM service client
const iamClient = new IAMClient({});
const stsClient = new STSClient({});

const getAccountId = async () => {
  const getCallerIdentityCommand = new GetCallerIdentityCommand({});
  const identity = await stsClient.send(getCallerIdentityCommand);
  return identity.Account;
};

const policiesName = {
  FullAccessPolicyEC2: 'FullAccessPolicyEC2',
  FullAccessPolicyS3: 'FullAccessPolicyS3',
  ReadAccessPolicyS3: 'ReadAccessPolicyS3'
};

const groupName = {
  FullAccessGroupEC2: 'FullAccessGroupEC2',
  FullAccessGroupS3: 'FullAccessGroupS3',
  ReadAccessGroupS3: 'ReadAccessGroupS3'
};

describe('IAM policies validation tests', () => {
  const getPolicyArn = async (policyName: string) => {
    const accountId = await getAccountId();
    return `arn:aws:iam::${accountId}:policy/${policyName}`;
  };

  const checkPolicy = async (policyName: string, actions: string | string[], effect: string) => {
    const policyArn = await getPolicyArn(policyName);

    // Retrieve the policy details
    const getPolicyCommand = new GetPolicyCommand({ PolicyArn: policyArn });
    const policy = await iamClient.send(getPolicyCommand);
    expect(policy.Policy).toBeDefined();

    // Retrieve the default policy version
    const getPolicyVersionCommand = new GetPolicyVersionCommand({
      PolicyArn: policyArn,
      VersionId: policy.Policy!.DefaultVersionId!
    });
    const policyVersion = await iamClient.send(getPolicyVersionCommand);
    expect(policyVersion.PolicyVersion).toBeDefined();

    // Decode and parse the policy document
    const document = decodeURIComponent(policyVersion.PolicyVersion!.Document!);
    const policyDocument = JSON.parse(document);

    // Verify the policy statements
    expect(policyDocument.Statement).toBeDefined();
    policyDocument.Statement.forEach((statement: any) => {
      expect(statement.Action).toEqual(actions);
      expect(statement.Effect).toEqual(effect);
      expect(statement.Resource).toEqual('*');
    });
  };

  test(`${policiesName.FullAccessPolicyEC2} has correct permissions`, async () => {
    await checkPolicy(policiesName.FullAccessPolicyEC2, 'ec2:*', 'Allow');
  });

  test(`${policiesName.FullAccessPolicyS3} has correct permissions`, async () => {
    await checkPolicy(policiesName.FullAccessPolicyS3, 's3:*', 'Allow');
  });

  test(`${policiesName.FullAccessPolicyS3} has correct permissions`, async () => {
    await checkPolicy(policiesName.ReadAccessPolicyS3, ['s3:Describe*', 's3:Get*', 's3:List*'], 'Allow');
  });
});

describe('IAM roles validation tests', () => {
  const rolePolicyMappings = [
    { roleName: 'FullAccessRoleEC2', policyName: policiesName.FullAccessPolicyEC2 },
    { roleName: 'FullAccessRoleS3', policyName: policiesName.FullAccessPolicyS3 },
    { roleName: 'ReadAccessRoleS3', policyName: policiesName.ReadAccessPolicyS3 }
  ];

  rolePolicyMappings.forEach(({ policyName, roleName }) => {
    test(`Role "${roleName}" has the correct policy "${policyName}" attached`, async () => {
      // Get the role
      const getRoleCommand = new GetRoleCommand({ RoleName: roleName });
      const roleResponse = await iamClient.send(getRoleCommand);
      expect(roleResponse.Role).toBeDefined();

      // Get attached policies for the role
      const listAttachedPoliciesCommand = new ListAttachedRolePoliciesCommand({ RoleName: roleName });
      const policiesResponse = await iamClient.send(listAttachedPoliciesCommand);
      expect(policiesResponse.AttachedPolicies).toBeDefined();

      // Check if the role has the correct policy attached
      const hasCorrectPolicy = policiesResponse.AttachedPolicies!.some(policy => policy.PolicyName === policyName);
      expect(hasCorrectPolicy).toBe(true);
    });
  });
});

describe('IAM user groups validation tests', () => {
  const groupPolicyMappings = [
    { groupName: groupName.FullAccessGroupEC2, policyName: policiesName.FullAccessPolicyEC2 },
    { groupName: groupName.FullAccessGroupS3, policyName: policiesName.FullAccessPolicyS3 },
    { groupName: groupName.ReadAccessGroupS3, policyName: policiesName.ReadAccessPolicyS3 }
  ];

  groupPolicyMappings.forEach(({ groupName, policyName }) => {
    test(`Group "${groupName}" has the correct policy "${policyName}" attached`, async () => {
      // Get the group
      const getGroupCommand = new GetGroupCommand({ GroupName: groupName });
      const groupResponse = await iamClient.send(getGroupCommand);
      expect(groupResponse.Group).toBeDefined();

      // Get attached policies for the group
      const listAttachedPoliciesCommand = new ListAttachedGroupPoliciesCommand({ GroupName: groupName });
      const policiesResponse = await iamClient.send(listAttachedPoliciesCommand);
      expect(policiesResponse.AttachedPolicies).toBeDefined();

      // Check if the group has the correct policy attached
      const hasCorrectPolicy = policiesResponse.AttachedPolicies!.some(policy => policy.PolicyName === policyName);
      expect(hasCorrectPolicy).toBe(true);
    });
  });
});

describe('IAM users and groups validation tests', () => {
  const userGroupMappings = [
    { userName: 'FullAccessUserEC2', groupName: groupName.FullAccessGroupEC2 },
    { userName: 'FullAccessUserS3', groupName: groupName.FullAccessGroupS3 },
    { userName: 'ReadAccessUserS3', groupName: groupName.ReadAccessGroupS3 }
  ];

  userGroupMappings.forEach(({ userName, groupName }) => {
    test(`User "${userName}" is a member of group "${groupName}"`, async () => {
      // Get the user to ensure it exists
      const getUserCommand = new GetUserCommand({ UserName: userName });
      const userResponse = await iamClient.send(getUserCommand);
      expect(userResponse.User).toBeDefined();

      // Get the groups for the user
      const listGroupsForUserCommand = new ListGroupsForUserCommand({
        UserName: userName
      });
      const groupsResponse = await iamClient.send(listGroupsForUserCommand);
      expect(groupsResponse.Groups).toBeDefined();

      // Check if the user is in the correct group
      const isInCorrectGroup = groupsResponse.Groups!.some(group => group.GroupName === groupName);
      expect(isInCorrectGroup).toBe(true);
    });
  });
});
