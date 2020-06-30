using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityNetCore.Models;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using QuoteApi.Models;

namespace IdentityNetCore.Controllers
{
    public class IdentityController : Controller
    {

        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailSender emailSender;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public IdentityController(UserManager<IdentityUser> userManager,RoleManager<IdentityRole> roleManager,SignInManager<IdentityUser> signInManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            this.emailSender = emailSender;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        public async Task<IActionResult> SignUp() {
            var model = new SignupViewModel() { Role = "Member"};
            return View(model);
        }

        [Authorize]
        public async Task<IActionResult> MFASetup() {
            const string provider = "aspnetidentity";
            var user = await _userManager.GetUserAsync(User);   //gives instance of currently logged in user
            await _userManager.ResetAuthenticatorKeyAsync(user);     //reset before generating a token
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            var qrCodeUrl = $"otpauth://totp/{provider}:{user.Email}?secret={token}&issuer={provider}&digits=6";
            var model = new MFAViewModel { Token = token, QRCodeUrl = qrCodeUrl};
            return View(model);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> MFASetup(MFAViewModel model) {
            if (ModelState.IsValid) {
                var user = await _userManager.GetUserAsync(User);
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (succeeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user,true);  //enable two factor authentication
                }
                else {
                    ModelState.AddModelError("Verify","Your MFA code could not be validated.");
                }
            }
            return View(model);
        }

        public ViewResult Index()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(SignupViewModel model)
        {
            if (ModelState.IsValid) 
            {   //if role is not there, add
                if (!(await _roleManager.RoleExistsAsync(model.Role))) {
                    var role = new IdentityRole { Name = model.Role };
                    var roleResult = await _roleManager.CreateAsync(role);
                    if (!roleResult.Succeeded) {
                        var errors = roleResult.Errors.Select(s=>s.Description);
                        ModelState.AddModelError("Role", string.Join(",", errors));
                        return View(model);
                    }
                }


                if ((await _userManager.FindByEmailAsync(model.Email)) == null)
                {
                    var user = new IdentityUser
                    {
                        Email = model.Email,     // from model
                        UserName = model.Email    // from inner def
                    };
                    var result = await _userManager.CreateAsync(user,model.Password);    //creating the user
                    
                   // user = await _userManager.FindByEmailAsync(model.Email);   //getting the user from database
                    //var token = await _userManager.GenerateEmailConfirmationTokenAsync(user); //creating a token for that user

                    if (result.Succeeded) {
                        //var confirmationLink =  Url.ActionLink("ConfirmEmail", "Identity", new { userId = user.Id, @token = token });
                        // await emailSender.SendEmailAsync("louis.gurung@selu.edu",user.Email,"Confirm your email address", "Here is the link :-) "+confirmationLink);
                        var claim = new Claim("Department", model.Department);
                        await _userManager.AddClaimAsync(user,claim);
                        await _userManager.AddToRoleAsync(user,model.Role);
                        return RedirectToAction("SignIn");
                    }
                    ModelState.AddModelError("Signup", string.Join("", result.Errors.Select(x => x.Description)));
                    return View(model);
                }
            }
            return View(model);
        }
                                              //identity has default string as userid
        //public async Task<IActionResult> ConfirmEmail(string userId, string token) {

        //    var user = await _userManager.FindByIdAsync(userId);
        //    var result = await _userManager.ConfirmEmailAsync(user,token);
        //    if (result.Succeeded) {
        //        return RedirectToAction("SignIn");
        //    }
        //    return new NotFoundResult();

        //}

        public IActionResult SignIn() {    //not really doing anything here so IActionResult
            return View(new SigninViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> SignIn(SigninViewModel model) {

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe,false);
                if (result.Succeeded)
                {
                    var user = await _userManager.FindByEmailAsync(model.Username);

                    //this is authorization using claims but we have already used Authorize for this.
                    //var userClaims = await _userManager.GetClaimsAsync(user);
                    //if (!userClaims.Any(c => c.Type == "Department"))
                    //{
                    //    ModelState.AddModelError("Claim", "User is not from any department");
                    //    return View(model);
                    //}
                    
                    if (await _userManager.IsInRoleAsync(user, "Member"))
                    {
                        return RedirectToAction("Member", "Home");
                    }
                    else if (await _userManager.IsInRoleAsync(user, "Admin"))
                    {
                        return RedirectToAction("Admin", "Home");
                    }
                    else
                        return RedirectToAction("Index");
                }
                else {
                    ModelState.AddModelError("Login", "Cannot Login.");
                }
            }
            else 
            {
                return View(model);
            }
            return View(model);
        }

        public async Task<IActionResult> AccessDenied (){ 
            return View();
        }

        public async Task<IActionResult> SignOut() {
            await _signInManager.SignOutAsync();
            return RedirectToAction();
        }


    }
}