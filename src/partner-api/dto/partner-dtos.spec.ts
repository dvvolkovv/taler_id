import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { DeleteUserQueryDto } from './delete-user-query.dto';
import { PatchUserDto } from './patch-user.dto';
import { ProvisionUserDto } from './provision-user.dto';
import { VerifyLinkCodeDto } from './verify-link-code.dto';

describe('partner API DTOs — validation messages are codes, not English sentences', () => {
  it('ProvisionUserDto: too-long firstName → invalid_first_name', async () => {
    const dto = plainToInstance(ProvisionUserDto, {
      externalId: 'e1',
      email: 'ivan@example.com',
      firstName: 'x'.repeat(101),
    });
    const errors = await validate(dto);
    const firstNameError = errors.find((e) => e.property === 'firstName');
    expect(Object.values(firstNameError?.constraints ?? {})).toEqual([
      'invalid_first_name',
    ]);
  });

  it('ProvisionUserDto: non-string externalId → invalid_external_id', async () => {
    const dto = plainToInstance(ProvisionUserDto, {
      externalId: 42,
      email: 'ivan@example.com',
    });
    const errors = await validate(dto);
    const externalIdError = errors.find((e) => e.property === 'externalId');
    expect(Object.values(externalIdError?.constraints ?? {})).toEqual(
      expect.arrayContaining(['invalid_external_id']),
    );
    expect(
      Object.values(externalIdError?.constraints ?? {}).every(
        (m) => m === 'invalid_external_id',
      ),
    ).toBe(true);
  });

  it('ProvisionUserDto: too-long email → invalid_email', async () => {
    const longEmail = `${'a'.repeat(250)}@x.co`;
    const dto = plainToInstance(ProvisionUserDto, {
      externalId: 'e1',
      email: longEmail,
    });
    const errors = await validate(dto);
    const emailError = errors.find((e) => e.property === 'email');
    expect(Object.values(emailError?.constraints ?? {})).toEqual(
      expect.arrayContaining(['invalid_email']),
    );
    expect(
      Object.values(emailError?.constraints ?? {}).every(
        (m) => m === 'invalid_email',
      ),
    ).toBe(true);
  });

  it('ProvisionUserDto: non-string lastName → invalid_last_name', async () => {
    const dto = plainToInstance(ProvisionUserDto, {
      externalId: 'e1',
      email: 'ivan@example.com',
      lastName: 42,
    });
    const errors = await validate(dto);
    const lastNameError = errors.find((e) => e.property === 'lastName');
    expect(Object.values(lastNameError?.constraints ?? {})).toEqual(
      expect.arrayContaining(['invalid_last_name']),
    );
  });

  it('ProvisionUserDto: too-long locale → invalid_locale', async () => {
    const dto = plainToInstance(ProvisionUserDto, {
      externalId: 'e1',
      email: 'ivan@example.com',
      locale: 'x'.repeat(11),
    });
    const errors = await validate(dto);
    const localeError = errors.find((e) => e.property === 'locale');
    expect(Object.values(localeError?.constraints ?? {})).toEqual([
      'invalid_locale',
    ]);
  });

  it('PatchUserDto: too-long firstName/lastName → invalid_first_name / invalid_last_name', async () => {
    const dto = plainToInstance(PatchUserDto, {
      firstName: 'x'.repeat(101),
      lastName: 'y'.repeat(101),
    });
    const errors = await validate(dto);
    const firstNameError = errors.find((e) => e.property === 'firstName');
    const lastNameError = errors.find((e) => e.property === 'lastName');
    expect(Object.values(firstNameError?.constraints ?? {})).toEqual([
      'invalid_first_name',
    ]);
    expect(Object.values(lastNameError?.constraints ?? {})).toEqual([
      'invalid_last_name',
    ]);
  });

  it('VerifyLinkCodeDto: bad code → invalid_code', async () => {
    const dto = plainToInstance(VerifyLinkCodeDto, { code: 'abcdef' });
    const errors = await validate(dto);
    const codeError = errors.find((e) => e.property === 'code');
    expect(Object.values(codeError?.constraints ?? {})).toEqual([
      'invalid_code',
    ]);
  });

  it('VerifyLinkCodeDto: non-string code → invalid_code', async () => {
    const dto = plainToInstance(VerifyLinkCodeDto, { code: 123456 });
    const errors = await validate(dto);
    const codeError = errors.find((e) => e.property === 'code');
    expect(
      Object.values(codeError?.constraints ?? {}).every(
        (m) => m === 'invalid_code',
      ),
    ).toBe(true);
    expect(Object.values(codeError?.constraints ?? {}).length).toBeGreaterThan(
      0,
    );
  });

  it('DeleteUserQueryDto: anything but the literal true/false → invalid_delete_account', async () => {
    const dto = plainToInstance(DeleteUserQueryDto, { deleteAccount: '1' });
    const errors = await validate(dto);
    const error = errors.find((e) => e.property === 'deleteAccount');
    expect(Object.values(error?.constraints ?? {})).toEqual([
      'invalid_delete_account',
    ]);
  });

  it('DeleteUserQueryDto: accepts the literal true/false strings, and omission', async () => {
    for (const value of ['true', 'false', undefined]) {
      const dto = plainToInstance(
        DeleteUserQueryDto,
        value === undefined ? {} : { deleteAccount: value },
      );
      const errors = await validate(dto);
      expect(errors).toEqual([]);
    }
  });
});
