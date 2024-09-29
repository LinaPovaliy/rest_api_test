<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class UserController extends AbstractController
{
    private EntityManagerInterface $entityManager;
    private ValidatorInterface $validator;

    public function __construct(EntityManagerInterface $entityManager, ValidatorInterface $validator)
    {
        $this->entityManager = $entityManager;
        $this->validator = $validator;
    }

    #[Route('/users', name: 'create_user', methods: ['POST'])]
    public function createUser(Request $request): JsonResponse
    {
        $data = $request->request->all();

        // Проверка на наличие обязательных параметров
        $requiredFields = ['name', 'email', 'password'];
        foreach ($requiredFields as $field) {
            if (!isset($data[$field])) {
                return new JsonResponse(['status' => 'Не заполнено обязательное поле', 'field' => $field], Response::HTTP_BAD_REQUEST);
            }
        }

        $user = new User();
        $user->setName($data['name'])
            ->setEmail($data['email'])
            ->setPassword(password_hash($data['password'], PASSWORD_BCRYPT));

        // Валидация
        $errors = $this->validator->validate($user);
        if (count($errors) > 0) {
            $errorMessages = [];
            foreach ($errors as $error) {
                $errorMessages[] = $error->getMessage();
            }

            return new JsonResponse(['status' => 'Ошибки валидации', 'errors' => $errorMessages], Response::HTTP_BAD_REQUEST);
        }

        // Сохранение пользователя в бд
        try {
            $this->entityManager->persist($user);
            $this->entityManager->flush();
        } catch (UniqueConstraintViolationException $e) {
            return new JsonResponse(['status' => 'Пользователь с таким email уже существует!'], Response::HTTP_CONFLICT);
        } catch (\Exception $e) {
            return new JsonResponse(['status' => 'Произошла ошибка при сохранении пользователя.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return new JsonResponse(['status' => 'Пользователь успешно создан!'], Response::HTTP_CREATED);
    }

    #[Route('/users/{id}', name: 'update_user', methods: ['PUT'])]
    public function updateUser(int $id, Request $request): JsonResponse
    {
        $data = $request->request->all();

        // Находим пользователя и обновляем его информацию
        $user = $this->entityManager->getRepository(User::class)->find($id);
        if (!$user) {
            return new JsonResponse(['status' => 'Пользователь не найден!'], Response::HTTP_NOT_FOUND);
        }

        if (!isset($data['name']) && !isset($data['email']) && !isset($data['password'])) {
            return new JsonResponse(['status' => 'Не указаны данные для обновления.'], Response::HTTP_BAD_REQUEST);
        }

        // Обновляем данные пользователя
        // Валидация имени
        if (isset($data['name'])) {
            if (empty(trim($data['name']))) {
                return new JsonResponse(['status' => 'Имя не может быть пустым.'], Response::HTTP_BAD_REQUEST);
            }
            $user->setName($data['name']);
        }

        // Валидация email
        if (isset($data['email'])) {
            if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
                return new JsonResponse(['status' => 'Некорректный формат email.'], Response::HTTP_BAD_REQUEST);
            }

            // Проверка уникальности email
            $existingUser = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $data['email']]);
            if ($existingUser && $existingUser->getId() !== $id) {
                return new JsonResponse(['status' => 'Пользователь с таким email уже существует!'], Response::HTTP_CONFLICT);
            }

            $user->setEmail($data['email']);
        }

        // Валидация пароля
        if (isset($data['password'])) {
            if (empty(trim($data['password']))) {
                return new JsonResponse(['status' => 'Пароль не может быть пустым.'], Response::HTTP_BAD_REQUEST);
            }

            // Хешируем пароль перед сохранением
            $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT);
            $user->setPassword($hashedPassword);
        }

        // Сохраняем изменения
        try {
            $this->entityManager->flush();
        } catch (\Exception $e) {
            return new JsonResponse(['status' => 'Произошла ошибка при обновлении пользователя.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        return new JsonResponse(['status' => 'Пользователь успешно обновлен!']);
    }

    #[Route('/users/{id}', name: 'delete_user', methods: ['DELETE'])]
    public function deleteUser(int $id): JsonResponse
    {
        // Находим и удаляем пользователя
        $user = $this->entityManager->getRepository(User::class)->find($id);

        if (!$user) {
            return new JsonResponse(['status' => 'Пользователь не найден!'], Response::HTTP_NOT_FOUND);
        }

        try {
            // Удаляем пользователя
            $this->entityManager->remove($user);
            $this->entityManager->flush();

            return new JsonResponse(['status' => 'Пользователь успешно удален!'], Response::HTTP_OK);
        } catch (\Exception $e) {
            // Обрабатываем любые ошибки при удалении
            return new JsonResponse(['status' => 'Произошла ошибка при удалении пользователя.'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    #[Route('/users/auth', name: 'auth_user', methods: ['POST'])]
    public function authUser(Request $request): JsonResponse
    {
        // Получаем email и пароль из запроса
        $data = $request->request->all();

        // Проверка на наличие обязательных полей
        if (!isset($data['email']) || !isset($data['password'])) {
            return new JsonResponse(['status' => 'Не заполнены обязательные поля'], Response::HTTP_BAD_REQUEST);
        }

        // Найдем пользователя по email
        try {
            $user = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $data['email']]);
        } catch (\Exception $e) {
            return new JsonResponse(['status' => 'Ошибка при попытке найти пользователя'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // Проверка, что пользователь найден и пароль верный
        if (!$user || !password_verify($data['password'], $user->getPassword())) {
            return new JsonResponse(['status' => 'Неверные учетные данные'], Response::HTTP_UNAUTHORIZED);
        }

        // Возвращаем информацию об успешной авторизации
        return new JsonResponse([
            'status' => 'Пользователь авторизован!',
            'user' => [
                'id' => $user->getId(),
                'name' => $user->getName(),
                'email' => $user->getEmail()
            ]
        ], Response::HTTP_OK);
    }

//    #[Route('/users/{id}', name: 'get_user_by_id', methods: ['GET'])]
//    public function getUserById(int $id): JsonResponse
//    {
//        // Найдем пользователя по id
//        $user = $this->entityManager->getRepository(User::class)->find($id);
//        if (!$user) {
//            return new JsonResponse(['status' => 'Пользователь не найден!'], Response::HTTP_NOT_FOUND);
//        }
//
//        // Возвращаем информацию о пользователе
//        return new JsonResponse([
//            'id' => $id,
//            'name' => $user->getName(),
//            'email' => $user->getEmail()
//        ]);
//    }
    #[Route('/users/search', name: 'get_user', methods: ['GET'])]
    public function getUserInfo(Request $request): JsonResponse
    {
        // Получаем параметры из запроса
        $id = $request->query->get('id');
        $name = $request->query->get('name');
        $email = $request->query->get('email');

        // Логика поиска по id
        if ($id) {
            $user = $this->entityManager->getRepository(User::class)->find($id);
            if (!$user) {
                return new JsonResponse(['status' => 'Пользователь с таким id не найден!'], Response::HTTP_NOT_FOUND);
            }
        }
        // Логика поиска по name
        elseif ($name) {
            $user = $this->entityManager->getRepository(User::class)->findOneBy(['name' => $name]);
            if (!$user) {
                return new JsonResponse(['status' => 'Пользователь с таким именем не найден!'], Response::HTTP_NOT_FOUND);
            }
        }
        // Логика поиска по email
        elseif ($email) {
            $user = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $email]);
            if (!$user) {
                return new JsonResponse(['status' => 'Пользователь с таким email не найден!'], Response::HTTP_NOT_FOUND);
            }
        }
        // Если параметры не указаны
        else {
            return new JsonResponse(['status' => 'Необходимо указать id, name или email'], Response::HTTP_BAD_REQUEST);
        }

        // Возвращаем информацию о пользователе
        return new JsonResponse([
            'id' => $user->getId(),
            'name' => $user->getName(),
            'email' => $user->getEmail()
        ], Response::HTTP_OK);
    }

}
