import 'package:conduit/conduit.dart';
import 'package:dart_backend/model/note.dart';

class User extends ManagedObject<_User> implements _User {
  Map<String, dynamic> toJson() => asMap();
}

@Table(name: 'users')
class _User {
  @primaryKey
  int? id;
  @Column(unique: true, indexed: true)
  String? userName;
  @Column(unique: true, indexed: true)
  String? email;
  @Serialize(input: true, output: false)
  String? password;

  @Column(omitByDefault: true)
  String? hashPassword;
  @Column(omitByDefault: true)
  String? salt;

  @Column(nullable: true)
  String? accessToken;
  @Column(nullable: true)
  String? refreshToken;

  ManagedSet<Note>? notesList;
}
