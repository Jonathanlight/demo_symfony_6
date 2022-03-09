<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class DefaultController extends AbstractController
{
    #[Route('/', name: 'homepage')]
    public function index(EntityManagerInterface $em): Response
    {
        /*$user = new User();
        $user->setRoles(['ROLE_USER']);
        $user->setUsername("user@gmail.com");
        $user->setEnabled(true);
        $user->setEmail("user@gmail.com");
        $user->setFullName("john doe");
        $pass = password_hash('root', PASSWORD_ARGON2I);
        $user->setPassword($pass);
        $em->persist($user);
        $em->flush();*/

        return $this->render('default/index.html.twig', [
            'controller_name' => 'DefaultController',
        ]);
    }
}
