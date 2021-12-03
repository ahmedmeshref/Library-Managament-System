$(document).ready(function () {
     $('#showpwd').on('click', function () {
          if ($('#pwd').attr('type') == 'password') {
               $('#pwd').attr('type', 'text');
          }
          else {
               $('#pwd').attr('type', 'password');
          }
     });
     $("#search").on('keyup', function () {
          var search = $(this).val().toLowerCase();
          $('#data tbody tr').filter(function () {
               $(this).toggle($(this).text().toLowerCase().indexOf(search) > -1);
          });
     });
});


$(function() {
  $('input[name="daterange"]').daterangepicker({
    opens: 'left'
  }, function(start, end, label) {
    console.log("A new date selection was made: " + start.format('YYYY-MM-DD') + ' to ' + end.format('YYYY-MM-DD'));
  });
});

let users = document.getElementById("user");