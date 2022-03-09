<?php

namespace App\Form;

use App\Entity\User;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class UserType extends AbstractType
{
    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => User::class,
        ]);
    }

    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('fullName', TextType::class, [
                'label' => 'user.fullname.name',
                'attr' => [
                    'class' => 'form-control',
                    'placeholder' => 'user.fullname.name',
                ]
            ])
            ->add('email', EmailType::class, [
                'label' => 'user.email.name',
                'attr' => [
                    'class' => 'form-control',
                    'placeholder' => 'user.email.name',
                ]
            ])
            ->add('password', RepeatedType::class, array(
                'type' => PasswordType::class,
                'help' => 'form.action.password.help',
                'first_options'  => array(
                    'label' => 'form.action.password',
                    'attr' => [
                        'class' => 'form-control',
                        'placeholder' => 'form.action.password',
                    ]
                ),
                'second_options' => array(
                    'label' => 'form.action.newPassword',
                    'attr' => [
                        'class' => 'form-control',
                        'placeholder' => 'form.action.newPassword',
                    ]
                ),
                'attr' => array(
                    'min' => 6,
                    'max' => 20
                )
            ))
        ;
    }
}
