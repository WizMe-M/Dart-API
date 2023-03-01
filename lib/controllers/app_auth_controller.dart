import 'dart:io';

import 'package:conduit/conduit.dart';
import 'package:dart_backend/model/user.dart';
import 'package:dart_backend/utils/app_response.dart';
import 'package:dart_backend/utils/app_utils.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';

class AppAuthController extends ResourceController {
  AppAuthController(this.managedContext);

  final ManagedContext managedContext;

  @Operation.post()
  Future<Response> signIn(@Bind.body() User user) async {
    if (user.password == null || user.userName == null) {
      return AppResponse.badRequest(
          message: 'Поля "userName" и "password" обязательны');
    }

    try {
      final found = await _findUser(managedContext, user.userName);
      if (found == null) {
        throw QueryException.input('Пользователь не найден', []);
      }

      // Генерация хэша пароля для дальнейшей проверки
      final requestHashPassword =
          generatePasswordHash(user.password ?? '', found.salt ?? '');

      if (requestHashPassword == found.hashPassword) {
        // Обновление токена пароля
        _updateTokens(found.id ?? -1, managedContext);

        // Получаем данные пользователя
        final newUser = await managedContext.fetchObjectWithID<User>(found.id);
        return AppResponse.ok(
            body: newUser!.backing.contents, message: 'Успешная авторизация');
      } else {
        throw QueryException.input('Неверный пароль', []);
      }
    } on QueryException catch (e) {
      return AppResponse.serverError(e, message: e.message);
    }
  }

  @Operation.put()
  Future<Response> signUp(@Bind.body() User user) async {
    if (user.password == null ||
        user.userName == null ||
        user.email == null ||
        user.password!.trim() == '' ||
        user.userName!.trim() == '' ||
        user.email!.trim() == '') {
      return AppResponse.badRequest(
          message: 'Поля "email", "userName" и "password" обязательны');
    }

    // Генерация соли
    final salt = generateRandomSalt();
    // Генерация хэша пароля
    final hashPassword = generatePasswordHash(user.password!, salt);

    try {
      late final int id;

      // Создаем транзакцию
      await managedContext.transaction((transaction) async {
        final qCreateUser = Query<User>(transaction)
          ..values.userName = user.userName
          ..values.email = user.email
          ..values.salt = salt
          ..values.hashPassword = hashPassword;

        // Добавление пользователя в базу данных
        final created = await qCreateUser.insert();
        // Сохраняем id
        id = created.id!;
        // Обновление токены
        _updateTokens(id, transaction);
      });

      final userData = await managedContext.fetchObjectWithID<User>(id);
      return AppResponse.ok(
          body: userData!.backing.contents, message: 'Успешная регистрация');
    } on QueryException catch (e) {
      return AppResponse.serverError(e, message: e.message);
    }
  }

  @Operation.post('refresh')
  Future<Response> refreshToken(
      @Bind.path('refresh') String refreshToken) async {
    try {
      final id = AppUtils.getIdFromToken(refreshToken);
      final user = await managedContext.fetchObjectWithID<User>(id);

      if (user!.refreshToken != refreshToken) {
        return AppResponse.unauthorized(message: 'Токен невалидный');
      }

      final refreshed = await _updateTokens(id, managedContext);
      return AppResponse.ok(body: refreshed, message: 'Токен успешно обновлен');
    } on QueryException catch (e) {
      return AppResponse.serverError(e, message: e.message);
    }
  }

  /// Поиск по имени пользователя в базе данных
  Future<User?> _findUser(ManagedContext context, String? userName) {
    final qFindUser = Query<User>(managedContext)
      ..where((x) => x.userName).equalTo(userName)
      ..returningProperties((x) => [x.id, x.salt, x.hashPassword]);

    return qFindUser.fetchOne();
  }

  Future<User?> _updateTokens(int id, ManagedContext transaction) async {
    final Map<String, String> tokens = _getTokens(id);

    final qUpdateTokens = Query<User>(transaction)
      ..where((x) => x.id).equalTo(id)
      ..values.accessToken = tokens['access']
      ..values.refreshToken = tokens['refresh'];

    return await qUpdateTokens.updateOne();
  }

  Map<String, String> _getTokens(int id) {
    final key = Platform.environment['SECRET_KEY'] ?? 'SECRET_KEY';
    final accessClaimSet =
        JwtClaim(maxAge: const Duration(hours: 1), otherClaims: {'id': id});
    final refreshClaimSet = JwtClaim(otherClaims: {'id': id});

    final tokens = <String, String>{
      'access': issueJwtHS256(accessClaimSet, key),
      'refresh': issueJwtHS256(refreshClaimSet, key),
    };
    return tokens;
  }
}
