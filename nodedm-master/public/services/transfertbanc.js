angular.module('MyApp')
    .factory('transfertbanc', function($http, $location, $rootScope, $alert, $window) {
        var token = $window.localStorage.token;
        if (token) {
            var payload = JSON.parse($window.atob(token.split('.')[1]));
            //takes a JSON-formatted string and converts it to a JavaScript object
            //window.atob: encoder
            $rootScope.currentUser = payload.user;
        }

        return {
            transfert: function(user) {
                return $http.post('/transfertbanc/transfert')
                    .success(function() {
                        $location.path('/transfert');
                        $alert({
                            title: 'Félicitations!',
                            content: 'Transfert réalisé.',
                            animation: 'fadeZoomFadeDown',
                            type: 'material',
                            duration: 3
                        });
                    })
                    .error(function(response) {
                        $alert({
                            title: 'Erreur!',
                            content: response.data,
                            animation: 'fadeZoomFadeDown',
                            type: 'material',
                            duration: 3
                        });
                    });
            }
        }
    });
