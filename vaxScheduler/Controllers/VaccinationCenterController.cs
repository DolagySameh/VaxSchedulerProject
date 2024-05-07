using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using vaxScheduler.Data.Model;
using vaxScheduler.Data;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using vaxScheduler.models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using static System.Net.Mime.MediaTypeNames;
using System.Drawing;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Processing;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Drawing.Processing;
using SixLabors.Fonts;
using SixLabors.ImageSharp.Formats.Png;
using vaxScheduler.models.repos;


namespace vaxScheduler.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class VaccinationCenterController : ControllerBase
    {
        public VaccinationCenterController(IRepository repo)
        {
            _repo = repo;
        }
        private readonly IRepository _repo;



        /*                          View patients that reserved vaccine from that vaccination center                               */
        [HttpGet("GetPatients-Reserved-withVaccinationCenter")]
        [Authorize(Roles = "VaccinationCenter")]
        public ActionResult<IEnumerable<ReservationDTO>> GetCenterReservations(int centerId)
        {
            return _repo.GetCenterReservations(centerId);
        }


        /*                                               Accept First Does                                  */
        [HttpPut("AcceptFirstDose")]
        [Authorize(Roles = "VaccinationCenter")]
        public ActionResult AcceptFirstDose(int reservationId)
        {
            return _repo.AcceptFirstDose(reservationId);
        }


        /*                                               Reject First Does                                  */
        [HttpDelete("RejectFirstDose")]
        [Authorize(Roles = "VaccinationCenter")]
        public ActionResult RejectFirstDose(int reservationId)
        {
            return _repo.RejectFirstDose(reservationId);    
        }



        /*                                      Accept Second Does                                  */

        [HttpPut("AcceptSecondDose")]
        [Authorize(Roles = "VaccinationCenter")]
        public ActionResult AcceptSecondDose(int reservationId)
        {
            return _repo.AcceptSecondDose(reservationId);
        }


        /*                                      Reject Second Does                                  */
        [HttpDelete("RejectSecondDose")]
        [Authorize(Roles = "VaccinationCenter")]
        public ActionResult RejectSecondDose(int reservationId)
        {
            return _repo.RejectSecondDose(reservationId);
        }


        /*                                      Upload Certificate                         */
        /*[HttpGet]
        [Route("api/certificate/{patientId}")]
        //[Authorize(Roles = "VaccinationCenter")]
        public async Task<IActionResult> GenerateCertificate(int patientId)
        {

                var reservations = await _db.Reservations.Where(r => r.PatientId == patientId).ToListAsync();
                if (reservations == null || !reservations.Any())
                {
                    return NotFound("Reservation data not found for the patient.");
                }
                var firstDoseReservation = reservations.FirstOrDefault(r => r.DoseNumber == "first-dose");
                var secondDoseReservation = reservations.FirstOrDefault(r => r.DoseNumber == "second-dose");
                if (firstDoseReservation == null)
                {
                    return BadRequest("First dose not found for the patient.");
                }
                if (secondDoseReservation == null)
                {
                    return BadRequest("Second dose not found for the patient.");
                }
                var patient = await _db.Users.FirstOrDefaultAsync(u => u.Id == patientId);
                var vaccine = await _db.Vaccines.FirstOrDefaultAsync(v => v.VaccineId == secondDoseReservation.VaccineId);
                var center = await _db.VaccinationCenters.FirstOrDefaultAsync(c => c.CenterId == secondDoseReservation.CenterId);
                var imageData = GenerateCertificateImage(patient.UserName, vaccine.VaccineName, center.CenterName);
                var certificate = new Certificate
                {
                    PatientId = patientId,
                    VaccineId = secondDoseReservation.VaccineId,
                    IssueDate = DateTime.Now,
                    CertificateFilePath = imageData
                };
                _db.Certificates.Add(certificate);
                await _db.SaveChangesAsync();
                return Ok("Certificate generated and saved successfully.");
            }
            
        

        private byte[] GenerateCertificateImage(string patientName, string vaccineName, string centerName)
        {
            using (var image = new Image<Rgba32>(600, 400))
            {                
                var blackColor = new Rgba32(0, 0, 0); // RGB values are all 0 for black
                var font = SystemFonts.CreateFont("Arial", 12);
                image.Mutate(ctx => {
                    ctx.DrawText($"Patient Name: {patientName}", font, blackColor, new SixLabors.ImageSharp.PointF(10, 10));
                    ctx.DrawText($"Vaccine Name: {vaccineName}", font, blackColor, new SixLabors.ImageSharp.PointF(10, 10));
                    ctx.DrawText($"Vaccination Center: {centerName}", font, blackColor, new SixLabors.ImageSharp.PointF(10, 10));
                });
                using (var stream = new MemoryStream())
                {
                    image.Save(stream, new PngEncoder());
                    return stream.ToArray();
                }
            }
        }
*/



    }
}