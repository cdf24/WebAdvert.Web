using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Linq;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.Runtime.Internal.Util;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebAdvert.Web.Models.Accounts;

namespace WebAdvert.Web.Controllers
{
    public class Accounts : Controller
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;

        public Accounts(SignInManager<CognitoUser> signInManager, UserManager<CognitoUser> userManager, CognitoUserPool pool)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _pool = pool;
        }

        public async Task<IActionResult> Signup()
        {
            var model = new SignupModel();

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                var user = _pool.GetUser(model.Email);

                if (user.Status != null)
                {
                    ModelState.AddModelError("UserExists", "User with this email already exists.");

                    return View(model);
                }

                user.Attributes.Add(CognitoAttribute.Name.ToString(), model.Email);

                var createdUser = await _userManager.CreateAsync(user, model.Password);

                if (createdUser.Succeeded)
                {
                    return RedirectToAction("Confirm");
                    //RedirectToPage("./Confirm");
                }
            }

            return View();
        }

        public async Task<IActionResult> Confirm()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Confirm(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user == null)
                {
                    ModelState.AddModelError("NotFound", "A user with the given email address was not found.");

                    return View(model);
                }

                var confirmResult = await ((CognitoUserManager<CognitoUser>) _userManager).ConfirmSignUpAsync(user, model.Code, true);

                if (confirmResult.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    foreach (var item in confirmResult.Errors)
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                    }

                    return View(model);
                }
            }

            return View(model);
        }

        public async Task<IActionResult> Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var loginResult = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

                if (loginResult.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("LoginError", "Email and Password do not match.");
                }
            }

            return View("Login", model);
        }
    }
}
